from flask import Flask, render_template, request

import libposts

app = Flask(__name__)


@app.route("/posts/<username>")
def view(username):
    posts = libposts.get_posts(username)
    return render_template("posts.view.html", posts=posts)        # stored XSS: {{ post.text | safe }}


@app.route("/posts_safe/<username>")
def view_safe(username):
    posts = libposts.get_posts(username)
    return render_template("posts.safe.html", posts=posts)        # autoescaped: not a finding


@app.route("/posts", methods=["POST"])
def create():
    libposts.post("someone", request.form.get("text"))
    return "ok"
