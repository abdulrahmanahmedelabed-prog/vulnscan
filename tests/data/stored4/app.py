import os, sqlite3, requests
from flask import Flask, request
app = Flask(__name__)
db = sqlite3.connect("x.db")

def table_for(kind):
    return db.execute("SELECT name FROM registry WHERE kind = ?", (kind,)).fetchone()[0]

@app.route("/w", methods=["POST"])
def w():
    db.execute(f"INSERT INTO {os.getenv('NOTES_TABLE')} (body) VALUES (?)", (request.form["b"],))
    db.execute(f"INSERT INTO {os.environ['TICKETS_TABLE']} (subject) VALUES (?)", (request.form["s"],))
    db.execute(f"INSERT INTO {os.getenv('AUDIT_TABLE')} (msg) VALUES (?)", (request.form["m"],))
    t = table_for("comments")
    db.execute(f"INSERT INTO {t} (comment) VALUES (?)", (request.form["c"],))

@app.route("/r")
def r():
    os.system(db.execute("SELECT body FROM notes_v2").fetchone()[0])
    os.system(db.execute("SELECT subject FROM tix_v2").fetchone()[0])
    os.system(db.execute("SELECT msg FROM audit_v3").fetchone()[0])
    remote = requests.get("https://config.internal/tables").json()["comments"]
    os.system(db.execute(f"SELECT comment FROM {remote}").fetchone()[0])
    os.system(db.execute("SELECT comment FROM archive").fetchone()[0])
    os.system(db.execute("SELECT title FROM archive").fetchone()[0])
