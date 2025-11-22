import sqlite3

def get_user(username):
    conn = sqlite3.connect('users.db')
    query = "SELECT * FROM users WHERE username='" + username + "'"
    cursor = conn.cursor()
    result = cursor.execute(query)
    return result.fetchone()
