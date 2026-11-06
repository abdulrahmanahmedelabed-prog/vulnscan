import sqlite3, os
from flask import Flask, request
app = Flask(__name__)
db = sqlite3.connect("app.db")

@app.route("/save", methods=["POST"])
def save():
    db.execute("INSERT INTO notes (body, title) VALUES (?, ?)", (request.form["body"], "fixed"))

@app.route("/run")
def run():
    row = db.execute("SELECT body FROM notes WHERE id = 1").fetchone()
    os.system("echo " + row[0])
    cur = db.cursor()
    cur.execute("SELECT title FROM notes")
    t = cur.fetchone()
    os.system("echo " + t[0])
    return "<p>" + row[0] + "</p>"
