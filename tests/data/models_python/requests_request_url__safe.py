# expect-none: DF010
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/p")
def p():
    request.args["u"]
    return requests.request("GET", "https://api.example.com/").text
