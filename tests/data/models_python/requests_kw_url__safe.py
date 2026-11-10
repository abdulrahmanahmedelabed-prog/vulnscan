# expect-none: DF010
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/p")
def p():
    return requests.get(url="https://api.example.com/", params={"q": request.args["u"]}, timeout=5).text
