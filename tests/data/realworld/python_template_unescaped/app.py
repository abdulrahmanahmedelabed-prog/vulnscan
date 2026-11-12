import jinja2
from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return render_template("search.html", query=q)          # search.html prints {{ query|safe }}: reflected XSS


@app.route("/search_safe")
def search_safe():
    q = request.args.get("q", "")
    return render_template("search_safe.html", query=q)     # autoescaped: not a finding


def make_env():
    return jinja2.Environment(loader=jinja2.FileSystemLoader("templates"), autoescape=False)   # CWE-79 / CWE-116


def make_env_safe():
    return jinja2.Environment(loader=jinja2.FileSystemLoader("templates"), autoescape=True)
