import os
from flask import Flask

app = Flask(__name__)


def show(req):
    return open(os.path.join("/srv/files", req.args["name"])).read()
