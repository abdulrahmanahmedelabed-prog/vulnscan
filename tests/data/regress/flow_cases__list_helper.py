import os
from flask import Flask, request
app = Flask(__name__)
def fill(buf, v):
    buf[0] = v
@app.route("/a")
def a():
    buf = [""]
    fill(buf, request.args["c"])
    os.system(buf[0])
