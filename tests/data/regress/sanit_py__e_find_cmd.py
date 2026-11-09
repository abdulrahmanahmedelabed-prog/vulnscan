from flask import Flask, request
import os
app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host")
    if host.find("..") != -1:
        return "bad"
    os.system("ping -c1 " + host)
    return "ok"
