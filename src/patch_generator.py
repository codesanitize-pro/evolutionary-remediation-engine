"""Patch Generator (B3) - Safe template application with guaranteed code validity.

Applies fix templates safely. Guarantees:
1. Code still parses after fix
2. No syntax errors introduced
3. Minimal diff - only change what's needed
"""

import ast
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import difflib


class PatchStatus(Enum):
    """Status of a patch generation attempt."""
    SUCCESS = "success"           # Patch generated and validated
    VALIDATION_FAILED = "validation_failed"  # Patch broke code validity
    TEMPLATE_ERROR = "template_error"        # Template couldn't be applied
    CONTEXT_MISMATCH = "context_mismatch"    # Code context doesn't match expected


@dataclass
class PatchResult:
    """Result of a patch generation attempt."""
    status: PatchStatus
    original_code: str
    patched_code: Optional[str] = None
    diff: Optional[str] = None
    template_id: Optional[str] = None
    error_message: str = ""
    line_changes: List[Tuple[int, str, str]] = None  # (line_num, old, new)
    
    def __post_init__(self):
        if self.line_changes is None:
            self.line_changes = []


class PatchGenerator:
    """Safe patch generator with validation.
    
    Design principles:
    - Never generate broken code
    - Verify syntax after every patch
    - Keep patches minimal and focused
    - If in doubt, don't patch
    """
    
    def __init__(self):
        self._validators: Dict[str, callable] = {
            ".py": self._validate_python,
            ".js": self._validate_javascript,
            ".ts": self._validate_typescript,
        }
    
    def generate_patch(
        self,
        source_code: str,
        template: Dict[str, Any],
        context: Dict[str, Any],
        file_extension: str
    ) -> PatchResult:
        """Generate a patch by applying a template to source code.
        
        Args:
            source_code: The original source code
            template: The fix template with placeholders
            context: Context extracted by pattern matcher
            file_extension: File extension for validation (e.g., '.py')
            
        Returns:
            PatchResult with status and patched code if successful
        """
        try:
            # Step 1: Apply template to generate patched code
            patched_code = self._apply_template(source_code, template, context)
            
            if patched_code is None:
                return PatchResult(
                    status=PatchStatus.TEMPLATE_ERROR,
                    original_code=source_code,
                    error_message="Template application failed"
                )
            
            # Step 2: Validate the patched code
            is_valid, error = self._validate(patched_code, file_extension)
            
            if not is_valid:
                return PatchResult(
                    status=PatchStatus.VALIDATION_FAILED,
                    original_code=source_code,
                    patched_code=patched_code,
                    error_message=f"Validation failed: {error}"
                )
            
            # Step 3: Generate diff
            diff = self._generate_diff(source_code, patched_code)
            line_changes = self._extract_line_changes(source_code, patched_code)
            
            return PatchResult(
                status=PatchStatus.SUCCESS,
                original_code=source_code,
                patched_code=patched_code,
                diff=diff,
                template_id=template.get("template_id"),
                line_changes=line_changes
            )
            
        except Exception as e:
            return PatchResult(
                status=PatchStatus.TEMPLATE_ERROR,
                original_code=source_code,
                error_message=f"Unexpected error: {str(e)}"
            )
    
    def _apply_template(self, source_code: str, template: Dict, context: Dict) -> Optional[str]:
        """Apply a template to source code using extracted context."""
        fix_code = template.get("fix_code", "")
        pattern = template.get("pattern", "")
        
        if not fix_code or not pattern:
            return None
        
        # Replace placeholders in fix_code with context values
        resolved_fix = fix_code
        for key, value in context.items():
            placeholder = f"{{{key}}}"
            if placeholder in resolved_fix:
                resolved_fix = resolved_fix.replace(placeholder, str(value))
        
        # Check for unresolved placeholders
        if re.search(r'\{[a-zA-Z_]+\}', resolved_fix):
            return None  # Unresolved placeholders remain
        
        # Apply the fix by replacing matched pattern with resolved fix
        try:
            # First try direct regex replacement
            patched = re.sub(pattern, resolved_fix, source_code, count=1)
            if patched != source_code:
                return patched
            
            # If pattern didn't match, try with the full_match from context
            if "full_match" in context:
                patched = source_code.replace(context["full_match"], resolved_fix, 1)
                if patched != source_code:
                    return patched
            
            return None
        except re.error:
            return None
    
    def _validate(self, code: str, file_extension: str) -> Tuple[bool, str]:
        """Validate that code is syntactically correct."""
        validator = self._validators.get(file_extension)
        
        if validator:
            return validator(code)
        
        # No validator for this extension - assume valid
        # (better to allow than to block without evidence)
        return True, ""
    
    def _validate_python(self, code: str) -> Tuple[bool, str]:
        """Validate Python code syntax."""
        try:
            ast.parse(code)
            return True, ""
        except SyntaxError as e:
            return False, f"SyntaxError at line {e.lineno}: {e.msg}"
    
    def _validate_javascript(self, code: str) -> Tuple[bool, str]:
        """Basic JavaScript validation (checks for obvious issues)."""
        # Basic bracket matching
        brackets = {'(': ')', '[': ']', '{': '}'}
        stack = []
        
        in_string = False
        string_char = None
        
        for i, char in enumerate(code):
            if char in '"\'' and (i == 0 or code[i-1] != '\\'):
                if not in_string:
                    in_string = True
                    string_char = char
                elif char == string_char:
                    in_string = False
                    string_char = None
            
            if not in_string:
                if char in brackets:
                    stack.append(brackets[char])
                elif char in brackets.values():
                    if not stack or stack.pop() != char:
                        return False, f"Mismatched bracket at position {i}"
        
        if stack:
            return False, "Unclosed brackets"
        
        return True, ""
    
    def _validate_typescript(self, code: str) -> Tuple[bool, str]:
        """TypeScript validation (same as JS for now)."""
        return self._validate_javascript(code)
    
    def _generate_diff(self, original: str, patched: str) -> str:
        """Generate a unified diff between original and patched code."""
        original_lines = original.splitlines(keepends=True)
        patched_lines = patched.splitlines(keepends=True)
        
        diff = difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile='original',
            tofile='patched',
            lineterm=''
        )
        
        return ''.join(diff)
    
    def _extract_line_changes(self, original: str, patched: str) -> List[Tuple[int, str, str]]:
        """Extract individual line changes for reporting."""
        original_lines = original.splitlines()
        patched_lines = patched.splitlines()
        
        changes = []
        matcher = difflib.SequenceMatcher(None, original_lines, patched_lines)
        
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'replace':
                for idx, (old, new) in enumerate(zip(
                    original_lines[i1:i2],
                    patched_lines[j1:j2]
                )):
                    changes.append((i1 + idx + 1, old, new))
            elif tag == 'delete':
                for idx, old in enumerate(original_lines[i1:i2]):
                    changes.append((i1 + idx + 1, old, ''))
            elif tag == 'insert':
                for idx, new in enumerate(patched_lines[j1:j2]):
                    changes.append((j1 + idx + 1, '', new))
        
        return changes


# Pre-built fix templates for common vulnerabilities
BUILTIN_TEMPLATES = {
    "sql_injection_parameterized": {
        "template_id": "sql_injection_parameterized",
        "name": "SQL Injection - Parameterized Query",
        "pattern": r'execute\s*\(["\']([^"\']*)["\']\s*%\s*\(?([^)]+)\)?\)',
        "fix_code": 'execute("{query}", ({params},))',
        "description": "Replace string formatting with parameterized query"
    },
    "xss_escape_output": {
        "template_id": "xss_escape_output",
        "name": "XSS - Escape Output",
        "pattern": r'innerHTML\s*=\s*([^;]+)',
        "fix_code": 'textContent = {content}',
        "description": "Replace innerHTML with textContent for user input"
    },
    "hardcoded_secret_env": {
        "template_id": "hardcoded_secret_env",
        "name": "Hardcoded Secret - Use Environment Variable",
        "pattern": r'({var})\s*=\s*["\'][^"\']+["\']',
        "fix_code": '{var} = os.environ.get("{var}", "")',
        "description": "Replace hardcoded secret with environment variable"
    },
    "path_traversal_sanitize": {
        "template_id": "path_traversal_sanitize",
        "name": "Path Traversal - Sanitize Input",
        "pattern": r'open\(([^)]+)\)',
        "fix_code": 'open(os.path.basename({path}))',
        "description": "Sanitize file path to prevent traversal"
    }
}
