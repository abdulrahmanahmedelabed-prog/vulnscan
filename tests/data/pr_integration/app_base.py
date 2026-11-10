from flask import Flask, request

from helpers import run_it

app = Flask(__name__)


@app.route("/run")
def run_cmd():
    c = "ls"
    run_it(c)
    return "ok"


@app.route("/calc")
def calc():
    return str(eval(request.args.get("e")))
