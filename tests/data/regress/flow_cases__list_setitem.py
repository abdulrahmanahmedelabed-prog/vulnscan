import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def a():
    argv = ["ls", "."]
    argv[1] = request.args["c"]
    os.system(argv[1])
