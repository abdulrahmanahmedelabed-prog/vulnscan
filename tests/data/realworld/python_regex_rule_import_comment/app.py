from flask import (
    Flask,
    render_template,
    render_template_string,
)

app = Flask(__name__)


@app.route("/")
def index():
    # rendered = render_template_string(user_template, title=title)
    return render_template_string("<h1>{{ title }}</h1>", title="hello")   # constant template: safe
