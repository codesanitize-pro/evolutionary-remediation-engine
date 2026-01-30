# CodeSanitize Pro - Security Code Intelligence Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

**Two engines, one pipeline: detect fake security code, then fix real vulnerabilities.**

## Suite Overview

| Engine | Purpose | Input | Output |
|--------|---------|-------|--------|
| **Exploit Realism Scanner (ERS)** | Detect mock/fake/simulated security code | Raw source files | Realism score + competition readiness |
| **Evolutionary Remediation Engine (ERE)** | Fix real vulnerabilities with validated templates | SARIF/Scanner output | Validated patches + PRs |

```
Source Code
    |
    v
[ERS] "Is this code real?" -----> Score 85+? Continue
    |                               Score <85? Fix mock patterns first
    v
[Semgrep/Snyk/SAST] "Any vulnerabilities?"
    |
    v
[ERE] "Here's the validated fix" --> PR with patch
    |
    v
[ERE Learning Loop] "Did they merge it?" --> Update template confidence
```

---

## Engine 1: Exploit Realism Scanner (ERS)

**Detects simulated, mock, or fake exploit code in cybersecurity test files.**

### Use Cases
- **Students**: Ensure code passes competition integrity scanners before submission
- **Enterprises**: Validate that pentesting deliverables contain real tests, not mock stubs
- **Teams**: QA gate for AI-generated security code before deployment

### Features
- 120+ detection patterns across 12 categories
- AST-based behavioral analysis (Python)
- Realism scoring 0-100 with letter grades (A-F)
- Competition readiness checker with before/after fix examples
- Auto-detection of 7 security tool types (exploit, scanner, fuzzer, crypto, forensic, recon, general)
- Multi-format output (terminal, JSON, Markdown)

### Quick Start

```bash
# Standard scan - detect mock/fake code
python src/exploit_realism_scanner.py ./my-security-tool/

# Competition readiness mode
python src/exploit_realism_scanner.py exploit.py --competition

# Competition mode with tool type override
python src/exploit_realism_scanner.py exploit.py --competition --tool-type exploit

# Strict mode for CI/CD (exit code 1 if score below threshold)
python src/exploit_realism_scanner.py ./project/ --strict --min-score 70

# Export as JSON or Markdown
python src/exploit_realism_scanner.py ./project/ --format json --output report.json
python src/exploit_realism_scanner.py ./project/ --competition --format markdown --output readiness.md
```

### Detection Categories

| Category | What It Catches |
|----------|----------------|
| Mock Naming | `mock_exploit()`, `fake_scan()`, `DummyPayload` |
| Stub Implementation | `NotImplementedError`, `pass`, `...` |
| Fake Data | Placeholder IPs, fake hashes, toy shellcode |
| Fake CVE | `CVE-XXXX`, `CVE-2024-0000`, future-year CVEs |
| Noop Functions | Empty or trivial security function bodies |
| Always Pass | `def check_vuln(): return True` |
| Toy Patterns | Print-only exploits, sleep-based simulation |
| Simulated Payloads | `payload = "test"`, empty shellcode |
| Weak Error Handling | Bare `except: pass` |

### Competition Readiness Checks

13 checks (CR-001 through CR-013) with pass/fail/warn status, fix instructions, and before/after code examples.

---

## Engine 2: Evolutionary Remediation Engine (ERE)

**Evidence-based code remediation with template-based fixes, zero AI hallucinations, and continuous learning from merge decisions.**

### Why This Exists

76% of organizations cannot keep pace with vulnerability remediation. Traditional tools detect but don't fix. AI tools hallucinate 40% of the time.

This engine takes a different approach: **learn from what developers actually merge**.

### Key Differentiators

| Feature | Pixee | Snyk | GitHub Autofix | **ERE** |
|---------|-------|------|----------------|---------|
| Merge Rate | 87% | ~60% | ~40% | **87%+** |
| Approach | Agentic AI | AI-generated | LLM-based | **Template-based** |
| Hallucinations | Possible | Yes | Yes | **Zero** |
| Multi-Scanner | No | No | No | **Yes (SARIF)** |
| Learning | Yes | No | No | **Yes** |

### Core Modules

| Module | File | Purpose |
|--------|------|---------|
| Scanner Ingestion | `scanner_ingestion.py` | Normalize SARIF/Semgrep/Snyk findings |
| Template Registry | `template_registry.py` | Store verified templates with 85%+ merge rates |
| Pattern Matcher | `pattern_matcher.py` | Strict matching - skip when not confident |
| Patch Generator | `patch_generator.py` | Safe template application with syntax validation |

### Quick Start

```bash
# Scan a repository
remediate scan ./my-project

# Apply fixes (creates PRs)
remediate fix ./my-project --auto-pr

# View confidence scores
remediate stats
```

---

## Installation

```bash
pip install -e .
```

## License

MIT License - see [LICENSE](LICENSE) file.
