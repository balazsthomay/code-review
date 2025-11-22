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

serious_diff = '''
diff --git a/user_auth.py b/user_auth.py
index abc123..def456 100644
--- a/user_auth.py
+++ b/user_auth.py
@@ -5,6 +5,12 @@ class UserAuth:
     def __init__(self):
         self.db = sqlite3.connect('users.db')
     
+    def authenticate(self, username, password):
+        query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
+        cursor = self.db.cursor()
+        result = cursor.execute(query)
+        return result.fetchone() is not None
+
'''

easy_diff = '''
diff --git a/utils.py b/utils.py
index abc123..def456 100644
--- a/utils.py
+++ b/utils.py
@@ -1,3 +1,8 @@
+def greet(name):
+    """Return a greeting message."""
+    return f"Hello, {name}!"
+
+
 def add(a, b):
     """Add two numbers."""
     return a + b
'''


async def main():
    if len(sys.argv) > 1:
        diff_path = sys.argv[1]
        with open(diff_path) as f:
            diff = f.read()
    else:
        diff = easy_diff

    report = await review_code(serious_diff, save_output=False, min_severity=5)


if __name__ == "__main__":
    asyncio.run(main())
