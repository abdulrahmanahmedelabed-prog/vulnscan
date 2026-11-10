# expect-none: DF011
import tarfile
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)


@app.post("/x")
def x():
    with tarfile.open("/srv/bundle.tar") as tar:
        tar.extractall(path="/srv/out/" + secure_filename(request.form["dest"]))
    return "ok"
