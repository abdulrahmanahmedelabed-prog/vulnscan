# expect: DF002
from fabric.api import sudo
from flask import Flask, request

app = Flask(__name__)


@app.route("/r")
def r():
    sudo("systemctl restart " + request.args["svc"])
    return "ok"
