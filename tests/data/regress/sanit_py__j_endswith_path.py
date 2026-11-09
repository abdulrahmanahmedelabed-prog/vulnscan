from flask import Flask, request, send_file
app = Flask(__name__)

@app.route("/dl")
def dl():
    fn = request.args.get("f")
    if not fn.endswith(".pdf"):
        return "bad"
    return open("/srv/docs/" + fn, "rb").read()
