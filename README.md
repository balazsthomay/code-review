# Multi-Agent Code Review System

An AI-powered code review system using specialized agents with RAG to analyze code changes.

## Architecture

```mermaid
flowchart TD
    Input[Git Diff] --> RAG[Vector DB<br/>5 Collections]

    RAG --> Agent1[Code Analyzer]
    RAG --> Agent2[Security Agent]
    RAG --> Agent3[Best Practices Agent]
    RAG --> Agent4[Test Coverage Agent]

    Input --> Agent1
    Input --> Agent2
    Input --> Agent3
    Input --> Agent4

    Agent1 --> Aggregator[Aggregator]
    Agent2 --> Aggregator
    Agent3 --> Aggregator
    Agent4 --> Aggregator

    Aggregator --> Output[PR Review Comment]

    style Input fill:#e1f5ff
    style RAG fill:#fff4e1
    style Agent1 fill:#e8f5e9
    style Agent2 fill:#e8f5e9
    style Agent3 fill:#e8f5e9
    style Agent4 fill:#e8f5e9
    style Aggregator fill:#f3e5f5
    style Output fill:#e1f5ff
```

### Core Components

**Multi-Agent System**
- Code Analyzer: Detects bugs, logic errors, and antipatterns
- Security Agent: Identifies security vulnerabilities
- Best Practices Agent: Checks code quality and maintainability
- Test Coverage Agent: Identifies missing test scenarios
- Aggregator: Deduplicates and merges findings

**RAG Knowledge Base**
- 5 vector collections with 82 patterns
- Security (43): OWASP Top 10 2021 with CWE mappings
- Best practices (20): PEP 8, PEP 257 guidelines
- Python gotchas (9): Common pitfalls
- Code review (8): Google Engineering Practices
- Refactoring (7): Cross-file patterns

**Evaluation Framework**
- Hybrid evaluation: location metrics + LLM semantic relevance
- Metrics: file recall, line precision/recall, LLM relevance, composite score
- Benchmarks: BugsInPy (502 bugs), CVE (17 vulnerabilities), synthetic (5 test cases)

## Setup

```bash
# Install dependencies
uv sync

# Build knowledge bases
uv run -m code_review.rag.build_security_kb
uv run -m code_review.rag.build_best_practices_kb
uv run -m code_review.rag.build_python_gotchas_kb
uv run -m code_review.rag.build_code_review_kb
uv run -m code_review.rag.build_refactoring_patterns_kb
```

## Usage

```bash
# Run on sample diff
uv run run_review.py

# Run on custom diff file
uv run run_review.py path/to/diff.diff

# Run benchmarks
uv run -m code_review.benchmarks.synthetic
uv run -m code_review.benchmarks.bugsinpy
uv run -m code_review.benchmarks.cve
```

## Performance

**BugsInPy:** 100% pass rate (18/18 bugs)

**CVE:** 94% pass rate (16/17 vulnerabilities), 94% security detection

**Synthetic:** 5 hand-crafted test cases covering SQL injection, logic bugs, code quality, multi-file security

## Project Structure

```
code_review/
├── __init__.py
├── schemas.py              # Pydantic models
├── agents.py               # 4 review agents + aggregator
├── pipeline.py             # Main orchestration
├── rag/
│   ├── retrieval.py        # Vector search functions
│   └── build_*.py          # Knowledge base builders (5)
└── benchmarks/
    ├── utils.py            # Evaluation utilities
    ├── synthetic.py        # Synthetic test cases
    ├── bugsinpy.py         # BugsInPy benchmark
    └── cve.py              # CVE benchmark

.github/
├── workflows/
│   └── code-review.yml     # GitHub Action workflow
└── actions/
    └── review-pr/          # Reusable action
```

## GitHub Action Integration

**To use this in your repositories:**

1. Add API keys as secrets in your repository (Settings → Secrets and variables → Actions):
   - `OPENAI_API_KEY`
   - `OPENROUTER_API_KEY`

2. Create `.github/workflows/code-review.yml`:
```yaml
name: AI Code Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run AI Code Review
        uses: balazsthomay/code-review@main
        with:
          openai_api_key: ${{ secrets.OPENAI_API_KEY }}
          openrouter_api_key: ${{ secrets.OPENROUTER_API_KEY }}
          min_severity: 5
```

Every PR will be automatically reviewed. Action passes if clean, fails and blocks merge if issues found.
