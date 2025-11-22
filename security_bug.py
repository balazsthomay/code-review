def authenticate(username, password):
    import sqlite3
    conn = sqlite3.connect('auth.db')
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE user='{username}' AND pass='{password}'"
    cursor = conn.cursor()
    result = cursor.execute(query)
    return result.fetchone() is not None
