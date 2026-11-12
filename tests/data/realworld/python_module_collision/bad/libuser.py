import sqlite3


def login(username):
    c = sqlite3.connect("u.db").cursor()
    return c.execute("SELECT * FROM users WHERE username = '%s'" % username).fetchone()
