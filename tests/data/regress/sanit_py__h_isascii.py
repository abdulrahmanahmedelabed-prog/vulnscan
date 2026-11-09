from flask import Flask, request
import os
app = Flask(__name__)

@app.route("/run3")
def run3():
    cmd = request.args.get("cmd")
    if cmd.isascii():
        os.system("echo " + cmd)
    return "ok"
