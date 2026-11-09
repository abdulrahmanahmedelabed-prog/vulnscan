from flask import Flask, request, abort
import sqlite3
app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name")
    if "<script>" in name:
        return "bad"
    return "<p>Hello " + name + "</p>"
