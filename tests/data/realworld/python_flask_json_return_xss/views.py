from flask import Flask, request

app = Flask(__name__)


@app.post("/add")
def add():
    a = request.form.get("a", type=int)          # converted to int by werkzeug: cannot carry markup
    return {"value": a}                          # dict -> application/json: not an HTML sink


@app.post("/echo")
def echo():
    return {"echo": request.form.get("q")}       # JSON response: not reflected XSS


@app.get("/html")
def html():
    return "<p>" + request.args.get("q", "") + "</p>"   # true positive: must stay reported
