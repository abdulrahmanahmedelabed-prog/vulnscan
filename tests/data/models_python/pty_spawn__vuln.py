# expect: DF003
import pty
from flask import Flask, request

app = Flask(__name__)


@app.route("/sh")
def sh():
    pty.spawn(request.args["prog"])
    return "ok"
