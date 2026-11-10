import ipaddress
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = str(ipaddress.ip_address(request.args.get("host", "")))
    subprocess.run(["ping", "-c", "1", host], check=False)
    return "sent"
