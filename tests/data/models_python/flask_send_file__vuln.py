# expect: DF005
from flask import Flask, request, send_file

app = Flask(__name__)


@app.route("/dl")
def dl():
    return send_file("/srv/files/" + request.args["name"])
