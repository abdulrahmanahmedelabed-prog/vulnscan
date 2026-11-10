# expect: DF003
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/sp")
def sp():
    os.posix_spawn(request.args["prog"], ["prog"], {})
    return "ok"
