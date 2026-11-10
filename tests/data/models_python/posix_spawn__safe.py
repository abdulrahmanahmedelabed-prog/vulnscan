# expect-none: DF003
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/sp")
def sp():
    request.args["prog"]
    os.posix_spawn("/usr/bin/uptime", ["uptime"], {})
    return "ok"
