import os
import uuid

from flask import Flask, render_template, request

app = Flask(__name__)
BLOG_DIR = os.path.join(app.root_path, "templates", "blogs")


def create_blog_post(title, content):
    filename = f"{uuid.uuid4()}.html"
    blog_template_content = f"""
{{% extends "base.html" %}}
{{% block content %}}<h3>{title}</h3><div>{content}</div>{{% endblock %}}
"""
    with open(os.path.join(BLOG_DIR, filename), "w") as f:
        f.write(blog_template_content)                 # stored SSTI: user text becomes template source
    return filename


def save_note(content):
    with open(os.path.join(BLOG_DIR, f"{uuid.uuid4()}.txt"), "w") as f:
        f.write(f"note: {content}\n")                  # plain data, no template tags: not a finding


@app.route("/create", methods=["POST"])
def create():
    name = create_blog_post(request.form.get("title"), request.form.get("content"))
    save_note(request.form.get("content"))
    return render_template(f"blogs/{name}")
BLOG_ROOT = BLOG_DIR
