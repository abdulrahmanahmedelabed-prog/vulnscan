import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def a():
    d = {"cmd": "ls"}
    e = d
    d["cmd"] = request.args["c"]
    os.system(e["cmd"])
