# expect-none: DF005
from flask import Flask, abort, request
from werkzeug.utils import safe_join

app = Flask(__name__)


@app.route("/read")
def read():
    path = safe_join("/srv/data", request.args["f"])
    if path is None:
        abort(404)
    with open(path) as fh:
        return fh.read()
