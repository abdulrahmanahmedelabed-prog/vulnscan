# expect-none: DF004
import psycopg2
from psycopg2 import sql
from flask import Flask, request

app = Flask(__name__)


@app.route("/t")
def t():
    conn = psycopg2.connect("")
    cur = conn.cursor()
    q = sql.SQL("SELECT * FROM {}").format(sql.Identifier(request.args["table"]))
    cur.execute(q)
    return "ok"
