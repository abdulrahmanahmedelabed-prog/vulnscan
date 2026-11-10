# expect: DF011
import zipfile
from flask import Flask, request

app = Flask(__name__)


@app.post("/x")
def x():
    with zipfile.ZipFile("/srv/bundle.zip") as zf:
        zf.extract("readme.txt", request.form["dest"])
    return "ok"
