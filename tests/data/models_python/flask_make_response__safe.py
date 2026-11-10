# expect-none: DF013
import html
from flask import Flask, make_response, request

app = Flask(__name__)


@app.route("/e")
def echo():
    return make_response("<p>" + html.escape(request.args["q"]) + "</p>")
