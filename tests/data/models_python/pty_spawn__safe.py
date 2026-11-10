# expect-none: DF003
import pty
from flask import Flask, request

app = Flask(__name__)


@app.route("/sh")
def sh():
    request.args["prog"]
    pty.spawn("/usr/bin/top")
    return "ok"
