# expect: DF007
from flask import Flask, request
from mako.template import Template

app = Flask(__name__)


@app.route("/t")
def t():
    return Template("Hi " + request.args["n"]).render()
