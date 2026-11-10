# expect: DF013
from flask import Flask, make_response, request

app = Flask(__name__)


@app.route("/e")
def echo():
    return make_response("<p>" + request.args["q"] + "</p>")
