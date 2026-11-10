# expect: DF007
import jinja2
from flask import Flask, request

app = Flask(__name__)
env = jinja2.Environment()


@app.route("/t")
def t():
    return env.from_string("Hi " + request.args["n"]).render()
