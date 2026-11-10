# expect: DF007
from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/hello")
def hello():
    return render_template_string("<h1>Hello " + request.args.get("name", "") + "</h1>")
