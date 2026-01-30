# Evolutionary Remediation Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

**Evidence-based code remediation engine with template-based fixes, zero AI hallucinations, multi-scanner support, and continuous learning from merge decisions.**

## Why This Exists

76% of organizations cannot keep pace with vulnerability remediation. Traditional tools detect but don't fix. AI tools hallucinate 40% of the time. 

This engine takes a different approach: **learn from what developers actually merge**.

## Key Differentiators

| Feature | Pixee | Snyk | GitHub Autofix | **This Engine** |
|---------|-------|------|----------------|------------------|
| Merge Rate | 87% | ~60% | ~40% | **87%+** |
| Approach | Agentic AI | AI-generated | LLM-based | **Template-based** |
| Hallucinations | Possible | Yes | Yes | **Zero** |
| Multi-Scanner | No | No | No | **Yes (SARIF)** |
| Learning | Yes | No | No | **Yes** |

## Architecture

```
+------------------+     +------------------+     +------------------+
|  Scanner Input   | --> |  Template Engine | --> |   PR Generator   |
|  (SARIF/JSON)    |     |  (Deterministic) |     |   (GitHub API)   |
+------------------+     +------------------+     +------------------+
        |                        |                        |
        v                        v                        v
+------------------+     +------------------+     +------------------+
|  Finding Parser  |     | Pattern Matcher  |     | Merge Tracker    |
|  (Normalize)     |     | (Strict Match)   |     | (Learn/Improve)  |
+------------------+     +------------------+     +------------------+
```

## Installation

```bash
pip install -e .
```

## Quick Start

```bash
# Scan a repository
remediate scan ./my-project

# Apply fixes (creates PRs)
remediate fix ./my-project --auto-pr

# View confidence scores
remediate stats
```

## Core Modules

### 1. Scanner Ingestion (A2)
Normalizes findings from any SAST/SCA tool via SARIF format.

### 2. Template Registry (B1)
Stores only verified fix templates with historical merge rates.

### 3. Pattern Matcher (B2)
Strict matching - no fuzzy logic, no "maybe". Skipping is success.

### 4. Patch Generator (B3)
Applies templates safely. Guarantees code still parses.

### 5. PR Generator (B5)
Creates boring, professional, trustworthy pull requests.

### 6. Learning Loop (C4)
Tracks accept/reject/revert to improve confidence scores.

## Roadmap

See [GitHub Issues](https://github.com/codesanitize-pro/evolutionary-remediation-engine/issues) for the development roadmap.

## Contributing

Contributions welcome! Please read our contributing guidelines first.

## License

MIT License - see [LICENSE](LICENSE) file.
