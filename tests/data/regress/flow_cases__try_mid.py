import os
from flask import Flask, request
app = Flask(__name__)
def validate(x):
    if ";" in x:
        raise ValueError(x)
@app.route("/a")
def a():
    try:
        cmd = request.args["c"]
        validate(cmd)
        cmd = "ls"
    except ValueError:
        os.system(cmd)
