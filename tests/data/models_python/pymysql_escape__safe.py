# expect-none: DF004
import pymysql
from pymysql.converters import escape_string
from flask import Flask, request

app = Flask(__name__)


@app.route("/t")
def t():
    conn = pymysql.connect()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM u WHERE n = '%s'" % escape_string(request.args["n"]))
    return "ok"
