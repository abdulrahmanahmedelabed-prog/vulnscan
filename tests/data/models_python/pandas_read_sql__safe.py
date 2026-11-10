# expect-none: DF004
import sqlite3
import pandas as pd
from flask import Flask, request

app = Flask(__name__)


@app.route("/r")
def r():
    df = pd.read_sql("SELECT * FROM t WHERE k = ?", sqlite3.connect("a.db"), params=(request.args["k"],))
    return df.to_json()
