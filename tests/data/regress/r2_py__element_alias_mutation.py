import os
from flask import Flask, request
app = Flask(__name__)
def fill(buf, v):
    buf.append(v)
@app.route('/a')
def a():
    conf = {"opts": []}
    opts = conf["opts"]
    opts.append(request.args['x'])
    os.system(conf["opts"][0])
@app.route('/b')
def b():
    conf = {"opts": []}
    inner = conf["opts"]
    fill(inner, request.args['x'])
    os.system(conf["opts"][0])
@app.route('/c')
def c():
    d = {}
    d.setdefault("k", []).append(request.args['x'])
    os.system(d["k"][0])
@app.route('/d')
def d():
    conf = {"opts": []}
    inner = conf["opts"]
    wrap = {}
    wrap["i"] = inner
    wrap["i"].append(request.args['x'])
    os.system(conf["opts"][0])
