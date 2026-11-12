import yaml
from flask import Flask, request

app = Flask(__name__)
ALLOWED = {"yaml", "yml"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    if file and allowed_file(file.filename):          # validates only the NAME, not the content
        data = yaml.load(file.stream, Loader=yaml.Loader)   # DF006 expected: content is still attacker-controlled
        return str(len(data))
    return "bad"
