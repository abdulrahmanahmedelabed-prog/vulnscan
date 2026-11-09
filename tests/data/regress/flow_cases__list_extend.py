import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def a():
    parts = []
    parts.extend(request.args.getlist("c"))
    os.system(parts[0])
