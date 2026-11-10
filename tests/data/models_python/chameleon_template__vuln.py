# expect: DF007
from chameleon import PageTemplate
from flask import Flask, request

app = Flask(__name__)


@app.route("/t")
def t():
    return PageTemplate("<p>" + request.args["n"] + "</p>")()
