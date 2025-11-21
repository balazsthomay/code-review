"""RAG retrieval functions for querying ChromaDB collections"""

import chromadb


def get_relevant_security_patterns(code_diff: str, n_results: int = 5) -> str:
    """Retrieve relevant security patterns from ChromaDB

    Args:
        code_diff: The code diff to analyze
        n_results: Number of patterns to retrieve (default: 5, increased to 15 for better coverage)

    Returns:
        Concatenated pattern documents as a single string
    """
    chroma_client = chromadb.PersistentClient(path="./chroma_db")
    security_collection = chroma_client.get_collection(name="security_patterns")
    results = security_collection.query(query_texts=[code_diff], n_results=n_results)
    return "\n\n".join(results['documents'][0]) if results['documents'][0] else ""


def get_relevant_best_practices_patterns(code_diff: str, n_results: int = 5) -> str:
    """Retrieve relevant best practices patterns from ChromaDB

    Args:
        code_diff: The code diff to analyze
        n_results: Number of patterns to retrieve (default: 5)

    Returns:
        Concatenated pattern documents as a single string
    """
    chroma_client = chromadb.PersistentClient(path="./chroma_db")
    best_practices_collection = chroma_client.get_collection(name="best_practices_patterns")
    results = best_practices_collection.query(query_texts=[code_diff], n_results=n_results)
    return "\n\n".join(results['documents'][0]) if results['documents'][0] else ""


def get_relevant_python_gotchas(code_diff: str, n_results: int = 3) -> str:
    """Retrieve relevant Python gotchas patterns from ChromaDB

    Args:
        code_diff: The code diff to analyze
        n_results: Number of patterns to retrieve (default: 3)

    Returns:
        Concatenated pattern documents as a single string
    """
    chroma_client = chromadb.PersistentClient(path="./chroma_db")
    python_gotchas_collection = chroma_client.get_collection(name="python_gotchas_patterns")
    results = python_gotchas_collection.query(query_texts=[code_diff], n_results=n_results)
    return "\n\n".join(results['documents'][0]) if results['documents'][0] else ""


def get_relevant_code_review_patterns(code_diff: str, n_results: int = 3) -> str:
    """Retrieve relevant code review patterns from ChromaDB

    Args:
        code_diff: The code diff to analyze
        n_results: Number of patterns to retrieve (default: 3)

    Returns:
        Concatenated pattern documents as a single string
    """
    chroma_client = chromadb.PersistentClient(path="./chroma_db")
    code_review_collection = chroma_client.get_collection(name="code_review_patterns")
    results = code_review_collection.query(query_texts=[code_diff], n_results=n_results)
    return "\n\n".join(results['documents'][0]) if results['documents'][0] else ""


def get_relevant_refactoring_patterns(code_diff: str, n_results: int = 5) -> str:
    """Retrieve relevant refactoring patterns from ChromaDB (multi-file changes, shotgun surgery, etc.)

    Args:
        code_diff: The code diff to analyze
        n_results: Number of patterns to retrieve (default: 5)

    Returns:
        Concatenated pattern documents as a single string
    """
    chroma_client = chromadb.PersistentClient(path="./chroma_db")
    refactoring_collection = chroma_client.get_collection(name="refactoring_patterns")
    results = refactoring_collection.query(query_texts=[code_diff], n_results=n_results)
    return "\n\n".join(results['documents'][0]) if results['documents'][0] else ""
