# expect: DF011
import shutil
from flask import Flask, request

app = Flask(__name__)


@app.post("/x")
def x():
    shutil.unpack_archive("/srv/bundle.zip", request.form["dest"])
    return "ok"
