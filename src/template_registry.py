"""Template Registry (B1) - Core component of the Evolutionary Remediation Engine.

Stores only verified fix templates with historical merge rates.
No AI hallucinations - all templates are human-validated from production fixes.
"""

import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime
import sqlite3


@dataclass
class FixTemplate:
    """A verified fix template with historical performance metrics."""
    template_id: str
    name: str
    description: str
    
    # Pattern matching
    vulnerability_type: str  # CWE ID or scanner-specific type
    language: str
    pattern: str  # AST pattern or regex for matching
    
    # The fix itself
    fix_code: str  # Template with placeholders
    context_required: List[str] = field(default_factory=list)
    
    # Evidence-based metrics
    total_applications: int = 0
    successful_merges: int = 0
    reverts: int = 0
    
    # Metadata
    source_pr: Optional[str] = None  # Original PR where this fix was validated
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_updated: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    @property
    def merge_rate(self) -> float:
        """Calculate historical merge success rate."""
        if self.total_applications == 0:
            return 0.0
        return (self.successful_merges - self.reverts) / self.total_applications
    
    @property
    def confidence_score(self) -> float:
        """Calculate confidence based on volume and success rate."""
        if self.total_applications < 5:
            return 0.0  # Not enough data
        base_score = self.merge_rate
        # Bonus for volume (max 10% bonus at 100+ applications)
        volume_bonus = min(0.1, self.total_applications / 1000)
        # Penalty for reverts (each revert costs 5%)
        revert_penalty = self.reverts * 0.05
        return max(0.0, min(1.0, base_score + volume_bonus - revert_penalty))


class TemplateRegistry:
    """Registry for storing and retrieving verified fix templates.
    
    Design principles:
    - Only templates with 85%+ merge rate are active
    - Templates below threshold are quarantined, not deleted
    - All changes are logged for audit
    """
    
    MINIMUM_MERGE_RATE = 0.85
    MINIMUM_APPLICATIONS = 5
    
    def __init__(self, db_path: str = "templates.db"):
        self.db_path = Path(db_path)
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize SQLite database for template storage."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS templates (
                    template_id TEXT PRIMARY KEY,
                    data JSON NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    quarantine_reason TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    template_id TEXT,
                    action TEXT,
                    details JSON,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_templates_vuln_type 
                ON templates(json_extract(data, '$.vulnerability_type'))
            """)
    
    def register_template(self, template: FixTemplate) -> str:
        """Register a new fix template.
        
        New templates start inactive until they meet minimum thresholds.
        """
        template_id = self._generate_id(template)
        template.template_id = template_id
        
        is_active = (
            template.total_applications >= self.MINIMUM_APPLICATIONS and
            template.merge_rate >= self.MINIMUM_MERGE_RATE
        )
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO templates (template_id, data, is_active) VALUES (?, ?, ?)",
                (template_id, json.dumps(asdict(template)), is_active)
            )
            self._log_action(conn, template_id, "register", {"is_active": is_active})
        
        return template_id
    
    def get_template(self, vuln_type: str, language: str) -> Optional[FixTemplate]:
        """Get the best active template for a vulnerability type.
        
        Returns the template with highest confidence score.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT data FROM templates 
                WHERE is_active = 1
                AND json_extract(data, '$.vulnerability_type') = ?
                AND json_extract(data, '$.language') = ?
            """, (vuln_type, language))
            
            best_template = None
            best_score = -1
            
            for row in cursor:
                data = json.loads(row['data'])
                template = FixTemplate(**data)
                if template.confidence_score > best_score:
                    best_score = template.confidence_score
                    best_template = template
            
            return best_template
    
    def record_outcome(self, template_id: str, merged: bool, reverted: bool = False) -> None:
        """Record the outcome of a template application.
        
        This is the learning loop - every merge/reject updates confidence.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT data, is_active FROM templates WHERE template_id = ?",
                (template_id,)
            )
            row = cursor.fetchone()
            if not row:
                return
            
            data = json.loads(row['data'])
            template = FixTemplate(**data)
            
            # Update metrics
            template.total_applications += 1
            if merged:
                template.successful_merges += 1
            if reverted:
                template.reverts += 1
            template.last_updated = datetime.utcnow().isoformat()
            
            # Check if template should be quarantined or activated
            should_be_active = (
                template.total_applications >= self.MINIMUM_APPLICATIONS and
                template.merge_rate >= self.MINIMUM_MERGE_RATE
            )
            
            quarantine_reason = None
            if not should_be_active and row['is_active']:
                quarantine_reason = f"Merge rate dropped to {template.merge_rate:.1%}"
            
            conn.execute("""
                UPDATE templates 
                SET data = ?, is_active = ?, quarantine_reason = ?, updated_at = CURRENT_TIMESTAMP
                WHERE template_id = ?
            """, (json.dumps(asdict(template)), should_be_active, quarantine_reason, template_id))
            
            self._log_action(conn, template_id, "outcome", {
                "merged": merged,
                "reverted": reverted,
                "new_merge_rate": template.merge_rate,
                "is_active": should_be_active
            })
    
    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        with sqlite3.connect(self.db_path) as conn:
            active = conn.execute("SELECT COUNT(*) FROM templates WHERE is_active = 1").fetchone()[0]
            quarantined = conn.execute("SELECT COUNT(*) FROM templates WHERE is_active = 0").fetchone()[0]
            
            return {
                "active_templates": active,
                "quarantined_templates": quarantined,
                "total_templates": active + quarantined
            }
    
    def _generate_id(self, template: FixTemplate) -> str:
        """Generate a unique ID for a template based on its content."""
        content = f"{template.vulnerability_type}:{template.language}:{template.pattern}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _log_action(self, conn: sqlite3.Connection, template_id: str, action: str, details: Dict) -> None:
        """Log an action to the audit trail."""
        conn.execute(
            "INSERT INTO audit_log (template_id, action, details) VALUES (?, ?, ?)",
            (template_id, action, json.dumps(details))
        )
