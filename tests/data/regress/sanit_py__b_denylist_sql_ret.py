from flask import Flask, request, abort
import sqlite3
app = Flask(__name__)

@app.route("/user")
def user():
    uid = request.args.get("id")
    if "--" in uid:
        return "bad"
    db = sqlite3.connect("x.db")
    return str(db.execute("SELECT * FROM users WHERE id = '" + uid + "'").fetchall())
