# expect: DF011
import shutil
from flask import Flask, request

app = Flask(__name__)


@app.post("/x")
def x():
    shutil.copy2(request.form["src"], "/srv/out/")
    return "ok"
