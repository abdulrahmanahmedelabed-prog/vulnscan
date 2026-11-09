import os
import re
from flask import Flask, request
app = Flask(__name__)
NAME_RE = re.compile(r"[\s\S]{1,64}")
@app.route('/a')
def a():
    f = request.args['f']
    if NAME_RE.fullmatch(f):
        return open(os.path.join("/srv", f)).read()
    return "no"
@app.route('/b')
def b():
    f = request.args['f']
    if re.fullmatch(r".{1,32}", f):
        return open("/srv/" + f).read()
    return "no"
