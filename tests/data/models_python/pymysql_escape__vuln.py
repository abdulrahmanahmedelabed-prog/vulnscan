# expect: DF004
import pymysql
from flask import Flask, request

app = Flask(__name__)


@app.route("/t")
def t():
    conn = pymysql.connect()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM u WHERE n = '%s'" % request.args["n"])
    return "ok"
