# expect: DF002
import paramiko
from flask import Flask, request

app = Flask(__name__)


@app.route("/r")
def r():
    client = paramiko.SSHClient()
    client.connect("build.internal")
    client.exec_command("deploy " + request.args["branch"])
    return "ok"
