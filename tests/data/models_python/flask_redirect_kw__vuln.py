# expect: DF008
from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/go")
def go():
    return redirect(location=request.args["to"])
