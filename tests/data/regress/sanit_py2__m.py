from flask import Flask, request
import html, os, shlex
app = Flask(__name__)

@app.route("/m1")
def m1():
    a = request.args.get("a")
    b = request.args.get("b")
    return "<p>" + html.escape(a) + b + "</p>"

@app.route("/m2")
def m2():
    a = request.args.get("a")
    b = request.args.get("b")
    os.system("ls " + shlex.quote(a) + " " + b)
    return "ok"

@app.route("/m3")
def m3():
    a = request.args.get("a")
    if request.args.get("c"):
        v = html.escape(a)
    else:
        v = a
    return "<p>" + v + "</p>"

@app.route("/m4")
def m4():
    a = request.args.get("a")
    b = request.args.get("b")
    s = "%s %s" % (html.escape(a), b)
    return s

@app.route("/m5")
def m5():
    a = request.args.get("a")
    b = request.args.get("b")
    return "<p>{}{}</p>".format(html.escape(a), b)

@app.route("/m6")
def m6():
    a = request.args.get("a")
    b = request.args.get("b")
    return f"<p>{html.escape(a)}{b}</p>"
