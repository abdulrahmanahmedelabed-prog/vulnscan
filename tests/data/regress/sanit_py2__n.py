from flask import Flask, request
import html, os, shlex
app = Flask(__name__)

@app.route("/n1")
def n1():
    a = request.args.get("a")
    b = request.args.get("b")
    v = html.escape(a) + b
    return "<p>" + v + "</p>"

@app.route("/n2")
def n2():
    a = request.args.get("a")
    b = request.args.get("b")
    cmd = "ls " + shlex.quote(a) + " " + b
    os.system(cmd)
    return "ok"
