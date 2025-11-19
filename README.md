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
- Security patterns collection: OWASP Top 10 2021 vulnerability patterns with CWE mappings (only A01 and A03 so far)
- Vector similarity search retrieves relevant patterns based on code diff
- Security Agent achieves 100% recall on security vulnerabilities with RAG

**3. Aggregator**
- Deduplicates findings across agents
- Merges related issues by file and line numbers
- Generates consolidated markdown reports

**4. Evaluation Framework**
- LLM-as-judge evaluation comparing findings against ground truth
- Metrics: Recall, Precision, F1 score
- 5 test cases covering SQL injection, logic bugs, code quality, and multi-file security issues

## Setup
```bash
# Install dependencies
uv sync

# Build security knowledge base
uv run build_security_kb.py
```

## Workflow

1. Input: Git diff of code changes
2. Each agent analyzes the diff independently
3. RAG augments Security Agent with relevant OWASP patterns
4. Aggregator merges findings and generates report
5. Evaluation framework measures performance against ground truth

## Project Structure
```
.
├── build_security_kb.py      # Builds ChromaDB with OWASP patterns
├── with_rag.ipynb           # Current code review pipeline
├── test-cases/                # Evaluation test diffs and ground truths
├── chroma_db/                 # Vector database (not committed)
└── pyproject.toml            # Dependencies
```

## Current Performance

Security Agent with RAG: 100% recall on security vulnerabilities across all test cases