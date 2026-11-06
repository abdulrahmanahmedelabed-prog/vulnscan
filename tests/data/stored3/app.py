import os, sqlite3, yaml
from flask import Flask, request
app = Flask(__name__)
db = sqlite3.connect("x.db")
TABLE = os.getenv("NOTES_TABLE", "notes")
cfg = yaml.safe_load(open("config.yaml"))

def insert_sql(table, column):
    return "INSERT INTO " + table + " (" + column + ") VALUES (?)"

def base_select(column):
    q = "SELECT " + column
    q += " FROM " + TABLE
    return q

@app.route("/w", methods=["POST"])
def w():
    db.execute(insert_sql(TABLE, "body"), (request.form["b"],))
    db.execute(f"INSERT INTO {cfg['db']['tickets']} (subject) VALUES (?)", (request.form["s"],))

@app.route("/r")
def r():
    row = db.execute(base_select("body") + " WHERE id = 1").fetchone()
    os.system(row[0])
    sql = "SELECT subject FROM {} WHERE id = ?".format(cfg["db"]["tickets"])
    t = db.execute(sql, (1,)).fetchone()
    os.system(t[0])
    other = db.execute("SELECT title FROM user_notes").fetchone()
    os.system(other[0])
