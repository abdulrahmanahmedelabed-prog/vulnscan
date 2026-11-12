import urllib.request
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    return urllib.request.urlopen(request.args["u"]).read()   # true positive: must stay reported
