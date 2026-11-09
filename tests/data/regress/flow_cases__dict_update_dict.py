import os
from flask import Flask, request
app = Flask(__name__)
@app.route("/a")
def a():
    defaults = {"q": ""}
    defaults.update(request.args.to_dict())
    cur = None
    cur.execute("SELECT * FROM t WHERE x='%s'" % defaults["q"])
