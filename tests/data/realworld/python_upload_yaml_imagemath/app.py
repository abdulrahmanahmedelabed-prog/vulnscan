import logging

import yaml
from flask import Flask, request
from PIL import Image, ImageMath

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    data = yaml.load(file.stream, Loader=yaml.Loader)           # DF006 expected (unsafe Loader, tainted stream)
    logger.error(f"processed {file.filename}")                  # DF016 expected (user-chosen filename in log)
    return str(data)


@app.route("/upload_safe", methods=["POST"])
def upload_safe():
    file = request.files["file"]
    return str(yaml.load(file.stream, Loader=yaml.SafeLoader))   # safe twin: not reported


@app.route("/image", methods=["POST"])
def image():
    img = Image.open(request.files["image"]).convert("L")
    expression = request.form.get("expression", "")
    out = ImageMath.eval(expression, a=img)                      # code injection (CVE-2022-22817 / CVE-2023-50447)
    return str(out)
