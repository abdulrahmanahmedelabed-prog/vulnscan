import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def a():
    c = ""
    match request.args["c"]:
        case c:
            os.system(c)
