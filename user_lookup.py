def find_user(email):
    import sqlite3
    conn = sqlite3.connect('app.db')
    query = f"SELECT * FROM users WHERE email='{email}'"
    result = conn.execute(query).fetchone()
    return result
