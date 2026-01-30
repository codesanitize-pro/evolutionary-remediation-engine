"""Scanner Ingestion (A2) - Normalize findings from any SAST/SCA tool via SARIF.

Supports multiple scanner formats and normalizes them to a common schema.
Primary input is SARIF - the industry standard for static analysis results.
"""

import json
from typing import Dict, List, Optional, Any, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
import hashlib


@dataclass
class NormalizedFinding:
    """A normalized vulnerability finding from any scanner."""
    finding_id: str
    vulnerability_type: str  # CWE ID when available
    severity: str           # critical, high, medium, low, info
    file_path: str
    line_number: int
    end_line: Optional[int] = None
    column: Optional[int] = None
    end_column: Optional[int] = None
    code_snippet: str = ""
    message: str = ""
    
    # Scanner metadata
    scanner_name: str = ""
    scanner_rule_id: str = ""
    scanner_rule_name: str = ""
    
    # Additional context
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    
    # Tracking
    ingested_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    raw_finding: Optional[Dict] = None


class ScannerIngestion:
    """Ingest and normalize findings from various security scanners.
    
    Primary format: SARIF (Static Analysis Results Interchange Format)
    Also supports: Semgrep JSON, CodeQL, Snyk, Checkmarx
    """
    
    # Severity mapping from various scanner formats
    SEVERITY_MAP = {
        # SARIF levels
        "error": "high",
        "warning": "medium", 
        "note": "low",
        "none": "info",
        # Semgrep severities
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "low",
        # General mappings
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "info",
    }
    
    def __init__(self):
        self._parsers = {
            "sarif": self._parse_sarif,
            "semgrep": self._parse_semgrep,
            "snyk": self._parse_snyk,
        }
    
    def ingest(self, data: Dict, format_type: str = "sarif") -> List[NormalizedFinding]:
        """Ingest scanner results and return normalized findings.
        
        Args:
            data: Parsed JSON data from scanner output
            format_type: Type of scanner format (sarif, semgrep, snyk)
            
        Returns:
            List of normalized findings
        """
        parser = self._parsers.get(format_type.lower())
        if not parser:
            raise ValueError(f"Unsupported format: {format_type}")
        
        return list(parser(data))
    
    def ingest_file(self, file_path: Path, format_type: Optional[str] = None) -> List[NormalizedFinding]:
        """Ingest scanner results from a file.
        
        Args:
            file_path: Path to the scanner output file
            format_type: Optional format type (auto-detected if not provided)
            
        Returns:
            List of normalized findings
        """
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        if format_type is None:
            format_type = self._detect_format(data)
        
        return self.ingest(data, format_type)
    
    def _detect_format(self, data: Dict) -> str:
        """Auto-detect the scanner format from the data structure."""
        # SARIF has a $schema or version field
        if "$schema" in data or data.get("version", "").startswith("2."):
            return "sarif"
        
        # Semgrep has results with check_id
        if "results" in data and data.get("results") and "check_id" in data["results"][0]:
            return "semgrep"
        
        # Snyk has vulnerabilities array
        if "vulnerabilities" in data:
            return "snyk"
        
        # Default to SARIF
        return "sarif"
    
    def _parse_sarif(self, data: Dict) -> Iterator[NormalizedFinding]:
        """Parse SARIF format findings."""
        for run in data.get("runs", []):
            tool = run.get("tool", {}).get("driver", {})
            scanner_name = tool.get("name", "unknown")
            
            # Build rule lookup
            rules = {r["id"]: r for r in tool.get("rules", [])}
            
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                rule = rules.get(rule_id, {})
                
                # Get location info
                locations = result.get("locations", [])
                if not locations:
                    continue
                
                location = locations[0].get("physicalLocation", {})
                artifact = location.get("artifactLocation", {})
                region = location.get("region", {})
                
                file_path = artifact.get("uri", "")
                if file_path.startswith("file://"):
                    file_path = file_path[7:]
                
                # Extract CWE if available
                cwe_id = None
                for tag in rule.get("properties", {}).get("tags", []):
                    if tag.startswith("CWE-"):
                        cwe_id = tag
                        break
                
                # Determine severity
                level = result.get("level", rule.get("defaultConfiguration", {}).get("level", "warning"))
                severity = self.SEVERITY_MAP.get(level, "medium")
                
                # Get code snippet if available
                snippet = region.get("snippet", {}).get("text", "")
                
                finding_id = self._generate_finding_id(
                    scanner_name, rule_id, file_path, region.get("startLine", 0)
                )
                
                yield NormalizedFinding(
                    finding_id=finding_id,
                    vulnerability_type=cwe_id or rule_id,
                    severity=severity,
                    file_path=file_path,
                    line_number=region.get("startLine", 0),
                    end_line=region.get("endLine"),
                    column=region.get("startColumn"),
                    end_column=region.get("endColumn"),
                    code_snippet=snippet,
                    message=result.get("message", {}).get("text", ""),
                    scanner_name=scanner_name,
                    scanner_rule_id=rule_id,
                    scanner_rule_name=rule.get("name", rule_id),
                    cwe_id=cwe_id,
                    tags=rule.get("properties", {}).get("tags", []),
                    raw_finding=result
                )
    
    def _parse_semgrep(self, data: Dict) -> Iterator[NormalizedFinding]:
        """Parse Semgrep JSON format findings."""
        for result in data.get("results", []):
            rule_id = result.get("check_id", "")
            
            # Extract CWE from metadata if available
            metadata = result.get("extra", {}).get("metadata", {})
            cwe_id = None
            cwe_list = metadata.get("cwe", [])
            if cwe_list:
                cwe_id = cwe_list[0] if isinstance(cwe_list, list) else cwe_list
            
            # Determine severity
            severity_str = result.get("extra", {}).get("severity", "WARNING")
            severity = self.SEVERITY_MAP.get(severity_str.upper(), "medium")
            
            finding_id = self._generate_finding_id(
                "semgrep", rule_id, result.get("path", ""), result.get("start", {}).get("line", 0)
            )
            
            yield NormalizedFinding(
                finding_id=finding_id,
                vulnerability_type=cwe_id or rule_id,
                severity=severity,
                file_path=result.get("path", ""),
                line_number=result.get("start", {}).get("line", 0),
                end_line=result.get("end", {}).get("line"),
                column=result.get("start", {}).get("col"),
                end_column=result.get("end", {}).get("col"),
                code_snippet=result.get("extra", {}).get("lines", ""),
                message=result.get("extra", {}).get("message", ""),
                scanner_name="semgrep",
                scanner_rule_id=rule_id,
                scanner_rule_name=metadata.get("name", rule_id),
                cwe_id=cwe_id,
                tags=metadata.get("category", []),
                raw_finding=result
            )
    
    def _parse_snyk(self, data: Dict) -> Iterator[NormalizedFinding]:
        """Parse Snyk JSON format findings."""
        for vuln in data.get("vulnerabilities", []):
            # Snyk includes file path in 'from' or 'targetFile'
            file_path = data.get("targetFile", "")
            
            # Extract CWE if available
            identifiers = vuln.get("identifiers", {})
            cwe_list = identifiers.get("CWE", [])
            cwe_id = cwe_list[0] if cwe_list else None
            
            severity = vuln.get("severity", "medium").lower()
            severity = self.SEVERITY_MAP.get(severity, severity)
            
            finding_id = self._generate_finding_id(
                "snyk", vuln.get("id", ""), file_path, 0
            )
            
            yield NormalizedFinding(
                finding_id=finding_id,
                vulnerability_type=cwe_id or vuln.get("id", ""),
                severity=severity,
                file_path=file_path,
                line_number=0,  # Snyk doesn't always provide line numbers
                message=vuln.get("title", ""),
                scanner_name="snyk",
                scanner_rule_id=vuln.get("id", ""),
                scanner_rule_name=vuln.get("title", ""),
                cwe_id=cwe_id,
                cvss_score=vuln.get("cvssScore"),
                raw_finding=vuln
            )
    
    def _generate_finding_id(self, scanner: str, rule_id: str, file_path: str, line: int) -> str:
        """Generate a unique, deterministic finding ID."""
        content = f"{scanner}:{rule_id}:{file_path}:{line}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def supported_formats(self) -> List[str]:
        """Return list of supported scanner formats."""
        return list(self._parsers.keys())
