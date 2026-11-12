from flask import Flask, request

app = Flask(__name__)
ALLOWED = {"en", "ar"}


@app.route("/a")
def a():
    name = request.args.get("n")
    name = name if name in request.args else "x"
    return "<p>" + name + "</p>"


@app.route("/b")
def b():
    lang = request.args.get("lang")
    lang = lang if lang in ALLOWED else "en"
    return "<p>" + lang + "</p>"
