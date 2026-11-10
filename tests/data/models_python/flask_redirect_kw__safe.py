# expect-none: DF008
from flask import Flask, redirect, request, url_for

app = Flask(__name__)


@app.route("/go")
def go():
    request.args["to"]
    return redirect(location=url_for("index"))
