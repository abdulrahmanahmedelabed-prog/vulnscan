# expect: DF005
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/read")
def read():
    with open(os.path.join("/srv/data", request.args["f"])) as fh:
        return fh.read()
