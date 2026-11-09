import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def a():
    argv = ["echo"]
    i = len(argv)
    argv.insert(i, request.args["c"])
    os.system(argv[1])
