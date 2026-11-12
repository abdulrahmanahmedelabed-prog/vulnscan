import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    parts = [p.strip() for p in request.args.getlist("p")]
    os.system("echo " + " ".join(parts))                  # tainted through the comprehension
    return "ok"


@app.route("/run_safe")
def run_safe():
    nums = [int(p) for p in request.args.getlist("p")]
    os.system("echo " + " ".join(str(n) for n in nums))   # numbers only: not a finding
    return "ok"


@app.route("/run_shadow")
def run_shadow():
    p = request.args.get("p")
    names = [p for p in ("a", "b")]                       # the loop variable hides the outer tainted `p`
    os.system("echo " + " ".join(names))
    return "ok"
