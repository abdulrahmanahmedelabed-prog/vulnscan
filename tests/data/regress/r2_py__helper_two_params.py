import os
import sqlite3
from flask import Flask, request
app = Flask(__name__)
db = sqlite3.connect("x")


def bq(table, ident):
    return 'SELECT * FROM ' + table + ' WHERE ident = ' + ident


def bq3(table, ident):
    t = 'SELECT * FROM ' + table
    t = t + ' WHERE ident = ' + ident
    return t


def pick(a, b, flag):
    if flag:
        r = a
    else:
        r = b
    return r


def run(prefix, arg):
    os.system(prefix + " " + arg)


@app.route('/x')
def x():
    v = request.args['id']
    db.execute(bq('items', v))
    db.execute(bq3('items', v))
    db.execute(pick('x', v, True))
    run('ls', v)
