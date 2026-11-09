import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def a():
    opts = {"cmd": "ls"}
    opts.update(request.args)
    os.system(opts["cmd"])
