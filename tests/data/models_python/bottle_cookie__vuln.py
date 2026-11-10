# expect: DF004
import sqlite3
from bottle import get, request


@get("/me")
def me():
    uid = request.get_cookie("uid")
    return str(sqlite3.connect("a.db").execute("SELECT * FROM u WHERE id = " + uid).fetchall())
