# expect-none: DF013
from flask import Flask, render_template, request
from markupsafe import Markup

app = Flask(__name__)


@app.route("/c")
def comment():
    return render_template("c.html", body=Markup("<p>%s</p>") % request.form["body"])
