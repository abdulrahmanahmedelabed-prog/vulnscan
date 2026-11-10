# expect: DF004
from flask import Flask, request

app = Flask(__name__)


@app.route("/t")
def t(cur):
    return cur.mogrify("SELECT * FROM u WHERE n = '" + request.args["n"] + "'")
