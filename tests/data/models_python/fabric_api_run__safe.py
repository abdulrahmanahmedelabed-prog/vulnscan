# expect-none: DF002
import shlex
from fabric.api import sudo
from flask import Flask, request

app = Flask(__name__)


@app.route("/r")
def r():
    sudo("systemctl restart " + shlex.quote(request.args["svc"]))
    return "ok"
