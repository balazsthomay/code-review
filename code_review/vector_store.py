"""Vector store utilities for codebase context

Provides functions to create and manage OpenAI vector stores for FileSearchTool.
"""

import os
from pathlib import Path
from openai import OpenAI


EXCLUDE_DIRS = {
    'node_modules', '.venv', 'venv', '__pycache__',
    '.git', '.github', 'dist', 'build', '.pytest_cache',
    'user-data', 'chroma_db', 'BugsInPy', 'cve_patches',
    'test-cases', '.mypy_cache', 'notebooks'
}

# Only OpenAI-supported formats
VALID_EXTENSIONS = {
    '.py', '.js', '.ts', '.tsx', '.jsx', '.md',
    '.json', '.txt', '.html', '.css', '.java',
    '.cpp', '.c', '.go', '.rb', '.php', '.cs'
}


def collect_codebase_files(root_dir: str = ".") -> list[str]:
    """Collect all relevant code files from the repository

    Args:
        root_dir: Root directory to scan (default: current directory)

    Returns:
        List of file paths to include in vector store
    """
    files = []
    for root, dirs, filenames in os.walk(root_dir):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for filename in filenames:
            if Path(filename).suffix in VALID_EXTENSIONS:
                filepath = os.path.join(root, filename)
                # Skip large files (>100KB)
                if os.path.getsize(filepath) < 100_000:
                    files.append(filepath)

    return files


def create_vector_store_from_codebase(api_key: str, root_dir: str = ".", name: str = "PR Review Context", expires_days: int = 1) -> str:
    """Create OpenAI vector store from current codebase

    Args:
        api_key: OpenAI API key
        root_dir: Root directory to scan (default: current directory)
        name: Name for the vector store
        expires_days: Days until auto-expiration (default: 1)

    Returns:
        vector_store_id: ID of the created vector store
    """
    client = OpenAI(api_key=api_key)

    print(f"Collecting codebase files from {root_dir}...")
    files = collect_codebase_files(root_dir)
    print(f"Found {len(files)} files to index")

    if not files:
        raise ValueError(f"No valid files found in {root_dir}")

    # Create vector store with auto-expiration
    print("Creating vector store...")
    vs = client.vector_stores.create(
        name=name,
        chunking_strategy={
            'type': 'static',
            'static': {
                'max_chunk_size_tokens': 1600,
                'chunk_overlap_tokens': 800
            }
        },
        expires_after={
            'anchor': 'last_active_at',
            'days': expires_days
        }
    )

    print(f"Uploading {len(files)} files to vector store...")

    # Upload files in batches (OpenAI limit: 500 files per batch)
    batch_size = 500
    for i in range(0, len(files), batch_size):
        batch_files = files[i:i + batch_size]
        file_streams = [open(path, "rb") for path in batch_files]

        try:
            batch = client.vector_stores.file_batches.upload_and_poll(
                vector_store_id=vs.id,
                files=file_streams
            )
            print(f"Batch {i//batch_size + 1}: {batch.status}")
        finally:
            # Close all file streams
            for f in file_streams:
                f.close()

    print(f"Vector store created: {vs.id}")
    return vs.id


def delete_vector_store(api_key: str, vector_store_id: str) -> None:
    """Delete a vector store

    Args:
        api_key: OpenAI API key
        vector_store_id: ID of vector store to delete
    """
    client = OpenAI(api_key=api_key)
    client.vector_stores.delete(vector_store_id)
    print(f"Deleted vector store: {vector_store_id}")
