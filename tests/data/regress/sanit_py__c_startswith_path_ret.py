from flask import Flask, request, abort
app = Flask(__name__)

@app.route("/file")
def get_file():
    fn = request.args.get("f")
    if not fn.startswith("uploads/"):
        return "bad"
    with open(fn) as fh:
        return fh.read()
