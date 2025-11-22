# Multi-Agent Code Review

An AI-powered code review system using multiple specialized agents with RAG (Retrieval-Augmented Generation) to analyze code changes for bugs, security vulnerabilities, best practices violations, and test coverage gaps.

## Architecture

### Core Components

**1. Multi-Agent System**
- **Code Analyzer Agent**: Detects bugs, logic errors, resource leaks, and antipatterns
- **Security Agent**: Identifies security vulnerabilities (SQL injection, command injection, path traversal, insecure deserialization, hardcoded secrets)
- **Best Practices Agent**: Checks code quality, style violations, and maintainability issues
- **Test Coverage Agent**: Identifies missing test scenarios and coverage gaps

**2. RAG Knowledge Base (ChromaDB)**
- **5 vector collections with 82 patterns total:**
  - Security patterns (43): Complete OWASP Top 10 2021 with CWE mappings
  - Best practices patterns (20): PEP 8, PEP 257 guidelines
  - Python gotchas patterns (9): Late binding, mutable defaults, etc.
  - Code review patterns (8): Google Engineering Practices, API breaking changes
  - Refactoring patterns (7): Shotgun surgery, cross-file dependencies, backward compatibility (Google AIP-180, Martin Fowler, Kent Beck TDD)
- Vector similarity search retrieves relevant patterns based on code diff
- All patterns sourced from authoritative references (OWASP, Google, Python.org, Refactoring Guru)

**3. Aggregator**
- Deduplicates findings across agents
- Merges related issues by file and line numbers
- Generates consolidated markdown reports

**4. Evaluation Framework**
- **Hybrid evaluation** combining automated location metrics + LLM semantic relevance
- **Metrics**: File recall, line precision/recall (with 5-line tolerance), LLM relevance (0.0-1.0), composite score
- **Benchmark**: BugsInPy dataset (502 real Python bugs from 17 production projects)
- **Tested on 20+ diverse bugs** across scrapy, ansible, keras, pandas, matplotlib, fastapi, etc.

- + 5 test cases covering SQL injection, logic bugs, code quality, and multi-file security issues

## Setup
```bash
# Install dependencies
uv sync

# Build all knowledge bases
uv run -m code_review.rag.build_security_kb
uv run -m code_review.rag.build_best_practices_kb
uv run -m code_review.rag.build_python_gotchas_kb
uv run -m code_review.rag.build_code_review_kb
uv run -m code_review.rag.build_refactoring_patterns_kb
```

## Usage

```python
from code_review import review_code

# Read your git diff
diff = open("changes.diff").read()

# Run the review
report = await review_code(diff, save_output=True)
print(report)
```

## Workflow

1. Input: Git diff of code changes
2. Each agent analyzes the diff independently with RAG-enhanced context
3. RAG retrieves relevant patterns from 5 knowledge bases (security, best practices, gotchas, code review, refactoring)
4. Aggregator deduplicates and merges findings into consolidated report
5. Evaluation framework measures performance against ground truth

## Project Structure
```
.
├── code_review/                      # Main package
│   ├── __init__.py                  # Exports review_code
│   ├── schemas.py                   # Pydantic models (8 schemas)
│   ├── agents.py                    # 5 agents (4 review + aggregator)
│   ├── pipeline.py                  # Main review pipeline
│   ├── rag/                         # RAG knowledge base
│   │   ├── retrieval.py            # 5 retrieval functions
│   │   ├── build_security_kb.py    # OWASP Top 10 2021 (43 patterns)
│   │   ├── build_best_practices_kb.py  # PEP 8/257 (20 patterns)
│   │   ├── build_python_gotchas_kb.py  # Python pitfalls (9 patterns)
│   │   ├── build_code_review_kb.py     # Google practices (8 patterns)
│   │   └── build_refactoring_patterns_kb.py  # Refactoring (7 patterns)
│   └── benchmarks/                  # Evaluation framework
│       ├── utils.py                # Shared evaluation utilities
│       ├── synthetic.py            # 5 synthetic test cases
│       ├── bugsinpy.py             # BugsInPy dataset (502 bugs)
│       └── cve.py                  # CVE dataset (17 CVEs)
├── final.ipynb                       # Demo notebook
├── notebooks/                        # Experimental notebooks
├── BugsInPy/                         # BugsInPy dataset
├── cve_patches/                      # CVE patch files
├── test-cases/                       # Synthetic test cases
├── chroma_db/                        # Vector database (not committed)
└── pyproject.toml                    # Dependencies
```

## Current Performance

**BugsInPy Benchmark:** 100% pass rate (18/18 valid bugs passed with composite score ≥ 60%)

**CVE Benchmark:** 94% pass rate (16/17 CVEs, 94% security detection rate)
- 17 real-world Python CVEs covering 11 CWE types (SQL Injection, Command Injection, XSS, Path Traversal, etc.)
- Projects: Django, Requests, urllib3, Setuptools, Jinja2, PyYAML, Pillow, Flask, Cryptography

**Key improvements:**
- Prompt engineering: Deletion analysis + chain-of-thought reasoning (70% → 100%)
- Multi-file awareness in aggregator for cross-file dependency detection
- Temperature optimization: default for review agents, 0.5 for aggregator/judge
- Schema validation: max 20 lines per finding + max_tokens=4000

**Typical results:**
- Most bugs achieve 100% composite score (perfect line recall + LLM relevance)
- Handles diverse bug types: logic errors, security vulnerabilities, style issues, missing tests
- Tested across 17 production Python projects (scrapy, ansible, keras, pandas, matplotlib, fastapi, etc.)


Note: the notebooks were built and tested in the root and subsequently moved to the notebooks/ folder after converting to python modules so the imports might not work there.

# Test comment
# Test comment
# Another test
