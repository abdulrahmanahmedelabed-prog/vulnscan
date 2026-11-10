# expect-none: DF005
import os
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)


@app.post("/upload")
def upload():
    f = request.files["doc"]
    f.save(os.path.join("/srv/uploads", secure_filename(f.filename)))
    return "ok"
