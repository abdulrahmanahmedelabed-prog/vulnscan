import importlib
from flask import Flask, request
app = Flask(__name__)
class Ops:
    def add(self): return 1
@app.route("/op")
def op():
    return str(getattr(Ops(), request.args["op"])())
@app.route("/safe")
def safe():
    return str(getattr(Ops(), "add")())
