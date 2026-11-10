# expect-none: DF011
import zipfile
from flask import Flask, request

app = Flask(__name__)


@app.post("/x")
def x():
    request.form["dest"]
    with zipfile.ZipFile("/srv/bundle.zip") as zf:
        zf.extract("readme.txt", "/srv/out")
    return "ok"
