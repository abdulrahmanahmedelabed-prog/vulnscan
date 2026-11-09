from flask import Flask, request
import re, os
app = Flask(__name__)

@app.route("/run")
def run():
    arg = request.args.get("arg")
    if re.search(r"rm ", arg):
        return "bad"
    os.system("echo " + arg)
    return "ok"
