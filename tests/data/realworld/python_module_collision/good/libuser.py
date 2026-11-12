import sqlite3


def login(username):
    c = sqlite3.connect("u.db").cursor()
    return c.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
