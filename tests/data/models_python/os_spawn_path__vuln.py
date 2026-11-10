# expect: DF003
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/sp")
def sp():
    os.spawnv(os.P_WAIT, request.args["prog"], ["prog"])
    return "ok"
