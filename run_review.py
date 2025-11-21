"""Run code review on a sample diff or provided diff file

Usage:
    uv run run_review.py                    # Use sample diff
    uv run run_review.py path/to/diff.diff  # Use custom diff file
"""

import sys
import asyncio
from code_review import review_code

# Sample diff for demonstration
SAMPLE_DIFF = """diff --git a/app/database.py b/app/database.py
index 1234567..abcdefg 100644
--- a/app/database.py
+++ b/app/database.py
@@ -10,7 +10,7 @@ def get_user_by_id(user_id):
     '''Fetch user from database by ID'''
     conn = sqlite3.connect('users.db')
     cursor = conn.cursor()
-    query = f"SELECT * FROM users WHERE id = {user_id}"
+    query = f"SELECT * FROM users WHERE id = '{user_id}'"
     cursor.execute(query)
     result = cursor.fetchone()
     return result
"""


async def main():
    if len(sys.argv) > 1:
        diff_path = sys.argv[1]
        with open(diff_path) as f:
            diff = f.read()
    else:
        diff = SAMPLE_DIFF

    report = await review_code(diff, save_output=True)


if __name__ == "__main__":
    asyncio.run(main())
