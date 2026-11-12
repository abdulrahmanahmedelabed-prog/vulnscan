from flask import Flask, request
import libuser

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def do_login():
    return str(libuser.login(request.form.get("username")))
