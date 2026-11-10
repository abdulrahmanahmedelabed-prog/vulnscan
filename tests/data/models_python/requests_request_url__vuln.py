# expect: DF010
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/p")
def p():
    return requests.request("GET", request.args["u"]).text
