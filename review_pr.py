"""GitHub Action script to run code review on PR"""

import asyncio
import os
import sys
from pathlib import Path

# Add the repo root to path so we can import code_review
repo_root = Path(__file__).parent
sys.path.insert(0, str(repo_root))

from code_review import review_code
import requests


async def main():
    # Get environment variables
    github_token = os.environ['GITHUB_TOKEN']
    pr_number = int(os.environ['PR_NUMBER'])
    repo_owner = os.environ['REPO_OWNER']
    repo_name = os.environ['REPO_NAME']
    min_severity = int(os.environ.get('MIN_SEVERITY', '5'))
    vector_store_id = os.environ.get('VECTOR_STORE_ID')
    
    # Get PR diff
    diff_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls/{pr_number}"
    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3.diff'
    }
    
    response = requests.get(diff_url, headers=headers)
    response.raise_for_status()
    diff = response.text
    
    print(f"Running code review on PR #{pr_number}")
    print(f"Minimum severity threshold: {min_severity}")
    if vector_store_id:
        print(f"Using codebase context (vector store: {vector_store_id})")

    # Run review
    report = await review_code(diff, save_output=False, min_severity=min_severity, vector_store_id=vector_store_id)
    
    # Check if there are issues
    if "No issues found" in report:
        print("✓ No issues found")
        sys.exit(0)
    
    # Post comment
    comment_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/issues/{pr_number}/comments"
    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    comment_body = report
    
    response = requests.post(comment_url, headers=headers, json={'body': comment_body})
    response.raise_for_status()
    
    print(f"✓ Posted review comment on PR #{pr_number}")
    
    # Exit with failure to block PR merge (remove these two if want to not block PR)
    print("Code review found issues - blocking PR")
    sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())