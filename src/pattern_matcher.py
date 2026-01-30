"""Pattern Matcher (B2) - Strict matching engine for vulnerability patterns.

No fuzzy logic, no "maybe". If we can't match with certainty, we skip.
Skipping is success - better no fix than a wrong fix.
"""

import re
import ast
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum


class MatchConfidence(Enum):
    """Confidence levels for pattern matches."""
    EXACT = "exact"       # Perfect AST match
    HIGH = "high"         # All critical patterns match
    SKIP = "skip"         # Not confident enough - skip this finding


@dataclass
class MatchResult:
    """Result of a pattern matching attempt."""
    matched: bool
    confidence: MatchConfidence
    template_id: Optional[str] = None
    context: Dict[str, Any] = None
    reason: str = ""
    
    def __post_init__(self):
        if self.context is None:
            self.context = {}


@dataclass  
class VulnerabilityFinding:
    """A normalized vulnerability finding from any scanner."""
    finding_id: str
    vulnerability_type: str  # CWE ID or normalized type
    severity: str
    file_path: str
    line_number: int
    column: Optional[int] = None
    code_snippet: str = ""
    scanner_name: str = ""
    scanner_rule_id: str = ""
    message: str = ""


class PatternMatcher:
    """Strict pattern matching engine.
    
    Design principles:
    - No fuzzy matching
    - No AI-generated patterns
    - Only well-tested, deterministic patterns
    - When in doubt, skip
    """
    
    def __init__(self):
        self._patterns: Dict[str, List[Dict]] = {}
        self._load_builtin_patterns()
    
    def match(self, finding: VulnerabilityFinding, source_code: str) -> MatchResult:
        """Attempt to match a finding against known patterns.
        
        Returns MatchResult with SKIP if not confident enough.
        """
        vuln_type = finding.vulnerability_type
        
        # Check if we have patterns for this vulnerability type
        if vuln_type not in self._patterns:
            return MatchResult(
                matched=False,
                confidence=MatchConfidence.SKIP,
                reason=f"No patterns registered for {vuln_type}"
            )
        
        # Extract the relevant code context
        code_context = self._extract_context(source_code, finding.line_number)
        if not code_context:
            return MatchResult(
                matched=False,
                confidence=MatchConfidence.SKIP,
                reason="Could not extract code context"
            )
        
        # Try each pattern for this vulnerability type
        for pattern in self._patterns[vuln_type]:
            result = self._try_pattern(pattern, code_context, finding)
            if result.matched:
                return result
        
        # No pattern matched with sufficient confidence
        return MatchResult(
            matched=False,
            confidence=MatchConfidence.SKIP,
            reason="No pattern matched with sufficient confidence"
        )
    
    def _try_pattern(self, pattern: Dict, code_context: str, finding: VulnerabilityFinding) -> MatchResult:
        """Try to match a specific pattern against code context."""
        pattern_type = pattern.get("type", "regex")
        
        if pattern_type == "regex":
            return self._match_regex(pattern, code_context, finding)
        elif pattern_type == "ast":
            return self._match_ast(pattern, code_context, finding)
        else:
            return MatchResult(
                matched=False,
                confidence=MatchConfidence.SKIP,
                reason=f"Unknown pattern type: {pattern_type}"
            )
    
    def _match_regex(self, pattern: Dict, code_context: str, finding: VulnerabilityFinding) -> MatchResult:
        """Match using regex patterns."""
        regex = pattern.get("pattern")
        if not regex:
            return MatchResult(
                matched=False,
                confidence=MatchConfidence.SKIP,
                reason="Pattern has no regex"
            )
        
        try:
            match = re.search(regex, code_context, re.MULTILINE | re.DOTALL)
            if match:
                # Extract captured groups as context
                context = match.groupdict() if match.groupdict() else {}
                context["full_match"] = match.group(0)
                
                return MatchResult(
                    matched=True,
                    confidence=MatchConfidence.HIGH,
                    template_id=pattern.get("template_id"),
                    context=context,
                    reason="Regex pattern matched"
                )
        except re.error as e:
            return MatchResult(
                matched=False,
                confidence=MatchConfidence.SKIP,
                reason=f"Regex error: {e}"
            )
        
        return MatchResult(
            matched=False,
            confidence=MatchConfidence.SKIP,
            reason="Regex did not match"
        )
    
    def _match_ast(self, pattern: Dict, code_context: str, finding: VulnerabilityFinding) -> MatchResult:
        """Match using AST patterns (Python only for now)."""
        if not finding.file_path.endswith(".py"):
            return MatchResult(
                matched=False,
                confidence=MatchConfidence.SKIP,
                reason="AST matching only supports Python"
            )
        
        try:
            tree = ast.parse(code_context)
        except SyntaxError:
            return MatchResult(
                matched=False,
                confidence=MatchConfidence.SKIP,
                reason="Could not parse code as Python"
            )
        
        ast_pattern = pattern.get("ast_pattern", {})
        node_type = ast_pattern.get("node_type")
        
        if not node_type:
            return MatchResult(
                matched=False,
                confidence=MatchConfidence.SKIP,
                reason="AST pattern missing node_type"
            )
        
        # Find matching nodes
        for node in ast.walk(tree):
            if node.__class__.__name__ == node_type:
                if self._ast_node_matches(node, ast_pattern):
                    context = self._extract_ast_context(node)
                    return MatchResult(
                        matched=True,
                        confidence=MatchConfidence.EXACT,
                        template_id=pattern.get("template_id"),
                        context=context,
                        reason="AST pattern matched exactly"
                    )
        
        return MatchResult(
            matched=False,
            confidence=MatchConfidence.SKIP,
            reason="AST pattern did not match"
        )
    
    def _ast_node_matches(self, node: ast.AST, pattern: Dict) -> bool:
        """Check if an AST node matches the pattern criteria."""
        checks = pattern.get("checks", [])
        
        for check in checks:
            attr = check.get("attr")
            expected = check.get("value")
            
            if not hasattr(node, attr):
                return False
            
            actual = getattr(node, attr)
            
            # Handle nested attribute access (e.g., "func.id")
            if isinstance(actual, ast.AST):
                if isinstance(expected, dict):
                    if not self._ast_node_matches(actual, {"checks": [expected]}):
                        return False
                elif hasattr(actual, "id"):
                    if actual.id != expected:
                        return False
            elif actual != expected:
                return False
        
        return True
    
    def _extract_ast_context(self, node: ast.AST) -> Dict[str, Any]:
        """Extract relevant context from an AST node for template application."""
        context = {
            "node_type": node.__class__.__name__,
            "lineno": getattr(node, "lineno", None),
            "col_offset": getattr(node, "col_offset", None),
        }
        
        # Add node-specific attributes
        if hasattr(node, "id"):
            context["id"] = node.id
        if hasattr(node, "name"):
            context["name"] = node.name
        if hasattr(node, "args"):
            context["args"] = ast.dump(node.args) if isinstance(node.args, ast.AST) else str(node.args)
        
        return context
    
    def _extract_context(self, source_code: str, line_number: int, context_lines: int = 10) -> Optional[str]:
        """Extract code context around a specific line."""
        lines = source_code.split("\n")
        
        if line_number < 1 or line_number > len(lines):
            return None
        
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        
        return "\n".join(lines[start:end])
    
    def register_pattern(self, vuln_type: str, pattern: Dict) -> None:
        """Register a new pattern for a vulnerability type."""
        if vuln_type not in self._patterns:
            self._patterns[vuln_type] = []
        self._patterns[vuln_type].append(pattern)
    
    def _load_builtin_patterns(self) -> None:
        """Load built-in patterns for common vulnerabilities."""
        # SQL Injection patterns
        self.register_pattern("CWE-89", {
            "type": "regex",
            "pattern": r'(?P<query>execute|cursor\.execute|query)\s*\(\s*["\'].*%.*["\']\s*%',
            "template_id": "sql_injection_parameterized",
            "description": "String formatting in SQL query"
        })
        
        self.register_pattern("CWE-89", {
            "type": "regex",
            "pattern": r'(?P<query>execute|cursor\.execute|query)\s*\([^)]*\+[^)]*\)',
            "template_id": "sql_injection_parameterized",
            "description": "String concatenation in SQL query"
        })
        
        # XSS patterns  
        self.register_pattern("CWE-79", {
            "type": "regex",
            "pattern": r'(?P<output>innerHTML|outerHTML|document\.write)\s*=',
            "template_id": "xss_escape_output",
            "description": "Direct DOM manipulation without escaping"
        })
        
        # Path Traversal patterns
        self.register_pattern("CWE-22", {
            "type": "regex",
            "pattern": r'(?P<func>open|read|write|readlines)\s*\([^)]*(?P<user_input>request|input|argv)',
            "template_id": "path_traversal_sanitize",
            "description": "User input used in file path"
        })
        
        # Hardcoded credentials
        self.register_pattern("CWE-798", {
            "type": "regex",
            "pattern": r'(?P<var>password|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{8,}["\']',
            "template_id": "hardcoded_secret_env",
            "description": "Hardcoded credential assignment"
        })
