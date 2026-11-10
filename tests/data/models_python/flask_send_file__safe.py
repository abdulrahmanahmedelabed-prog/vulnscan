# expect-none: DF005
from flask import Flask, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)


@app.route("/dl")
def dl():
    return send_file("/srv/files/" + secure_filename(request.args["name"]))
