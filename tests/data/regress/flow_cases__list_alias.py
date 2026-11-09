import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def a():
    a = []
    b = a
    a.append(request.args["c"])
    os.system(b[0])
