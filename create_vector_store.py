"""Create vector store from codebase for GitHub Action

This script creates an OpenAI vector store from the current repository
and outputs the vector_store_id for use in the review pipeline.
"""

import os
import sys


def create_vector_store_silent(api_key, root_dir, name, expires_days):
    """Create vector store with progress to stderr, return vector_store_id"""
    from code_review.vector_store import collect_codebase_files
    from openai import OpenAI

    client = OpenAI(api_key=api_key)

    print("Collecting codebase files...", file=sys.stderr)
    files = collect_codebase_files(root_dir)
    print(f"Found {len(files)} files to index", file=sys.stderr)

    if not files:
        raise ValueError(f"No valid files found in {root_dir}")

    print("Creating vector store...", file=sys.stderr)
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

    print(f"Uploading {len(files)} files...", file=sys.stderr)
    batch_size = 500
    for i in range(0, len(files), batch_size):
        batch_files = files[i:i + batch_size]
        file_streams = [open(path, "rb") for path in batch_files]

        try:
            batch = client.vector_stores.file_batches.upload_and_poll(
                vector_store_id=vs.id,
                files=file_streams
            )
            print(f"Batch {i//batch_size + 1}: {batch.status}", file=sys.stderr)
        finally:
            for f in file_streams:
                f.close()

    print(f"Vector store created: {vs.id}", file=sys.stderr)
    return vs.id


def main():
    openai_api_key = os.getenv('OPENAI_API_KEY')

    if not openai_api_key:
        print("Error: OPENAI_API_KEY environment variable not set", file=sys.stderr)
        sys.exit(1)

    try:
        vector_store_id = create_vector_store_silent(api_key=openai_api_key, root_dir=".", name="PR Review Context", expires_days=1)

        # Output for GitHub Actions (stdout only has key=value format)
        print(f"vector_store_id={vector_store_id}")

    except Exception as e:
        print(f"Error creating vector store: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
