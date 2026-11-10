# expect: DF012
import pydoc
from flask import Flask, request

app = Flask(__name__)


@app.route("/plugin")
def plugin():
    return str(pydoc.locate(request.args["cls"]))
