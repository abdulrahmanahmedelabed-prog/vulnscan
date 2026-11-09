from flask import Flask, request
import sqlite3
app = Flask(__name__)

@app.route("/img")
def img():
    name = request.args.get("name")
    if name.endswith(".png"):
        db = sqlite3.connect("x.db")
        return str(db.execute("SELECT * FROM images WHERE name = '" + name + "'").fetchall())
    return "no"
