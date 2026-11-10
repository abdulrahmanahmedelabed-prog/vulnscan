# expect-none: DF011
import shutil
from flask import Flask, request

app = Flask(__name__)


@app.post("/x")
def x():
    request.form["dest"]
    shutil.unpack_archive("/srv/bundle.zip", "/srv/out")
    return "ok"
