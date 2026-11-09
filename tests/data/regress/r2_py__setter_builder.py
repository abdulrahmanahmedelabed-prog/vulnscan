import os
from flask import Flask, request
app = Flask(__name__)
class Cmd:
    def __init__(self):
        self.parts = []
    def add(self, p):
        self.parts.add(p)
        return self
    def build(self):
        return " ".join(self.parts)
class Cmd2:
    def __init__(self):
        self.s = ""
    def set(self, p):
        self.s = p
    def build(self):
        return self.s
@app.route('/x')
def x():
    c = Cmd()
    c.add("ping")
    c.add(request.args['h'])
    os.system(c.build())
    d = Cmd2()
    d.set(request.args['h'])
    os.system(d.build())
