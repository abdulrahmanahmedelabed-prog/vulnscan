# expect: DF005
import os
from flask import Flask, request

app = Flask(__name__)


@app.post("/upload")
def upload():
    f = request.files["doc"]
    f.save(os.path.join("/srv/uploads", f.filename))
    return "ok"
