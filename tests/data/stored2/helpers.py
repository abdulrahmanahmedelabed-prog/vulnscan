import sqlite3, os
from flask import Flask, request
app = Flask(__name__)
db = sqlite3.connect("x.db")

def save(table, data):
    cols = ", ".join(data.keys())
    db.execute(f"INSERT INTO {table} ({cols}) VALUES (?)", list(data.values()))

def fetch(table, row_id):
    return db.execute(f"SELECT * FROM {table} WHERE id = ?", (row_id,)).fetchone()

@app.route("/w", methods=["POST"])
def w():
    save("messages", {"text": request.form["t"]})
    save("audit", {"note": "constant"})

@app.route("/r")
def r():
    m = fetch("messages", 1)
    os.system(m[0])
    a = fetch("audit", 1)
    os.system(a[0])
