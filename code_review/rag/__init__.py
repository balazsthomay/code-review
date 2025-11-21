"""RAG (Retrieval-Augmented Generation) knowledge base module

Contains:
- Vector database builders for 5 pattern collections (82 total patterns)
- Retrieval functions for querying relevant patterns
"""

from code_review.rag.retrieval import (
    get_relevant_security_patterns,
    get_relevant_best_practices_patterns,
    get_relevant_python_gotchas,
    get_relevant_code_review_patterns,
    get_relevant_refactoring_patterns,
)

__all__ = [
    "get_relevant_security_patterns",
    "get_relevant_best_practices_patterns",
    "get_relevant_python_gotchas",
    "get_relevant_code_review_patterns",
    "get_relevant_refactoring_patterns",
]
