import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def a():
    q = ["echo", request.args["c"]]
    head = q.pop(0)
    os.system(q[0])
