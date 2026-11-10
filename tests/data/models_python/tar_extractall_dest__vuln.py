# expect: DF011
import tarfile
from flask import Flask, request

app = Flask(__name__)


@app.post("/x")
def x():
    with tarfile.open("/srv/bundle.tar") as tar:
        tar.extractall(path=request.form["dest"])
    return "ok"
