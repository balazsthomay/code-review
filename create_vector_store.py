"""Create vector store from codebase for GitHub Action

This script creates an OpenAI vector store from the current repository
and outputs the vector_store_id for use in the review pipeline.
"""

import os
import sys
from code_review.vector_store import create_vector_store_from_codebase


def main():
    openai_api_key = os.getenv('OPENAI_API_KEY')

    if not openai_api_key:
        print("Error: OPENAI_API_KEY environment variable not set", file=sys.stderr)
        sys.exit(1)

    try:
        vector_store_id = create_vector_store_from_codebase(api_key=openai_api_key, root_dir=".", name="PR Review Context", expires_days=1)

        # Output for GitHub Actions
        print(f"vector_store_id={vector_store_id}")

    except Exception as e:
        print(f"Error creating vector store: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
