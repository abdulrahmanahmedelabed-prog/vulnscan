from flask import Flask, request
import os
app = Flask(__name__)

@app.route("/run2")
def run2():
    cmd = request.args.get("cmd")
    if "ls -la /tmp".startswith(cmd):
        os.system(cmd)
    return "ok"
