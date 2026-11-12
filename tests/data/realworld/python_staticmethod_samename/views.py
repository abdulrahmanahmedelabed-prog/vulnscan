import sqlite3
from flask import Flask, request

from dao.student import Student

app = Flask(__name__)


@app.route("/students", methods=["POST"])
def students():
    Student.create(sqlite3.connect("x.db"), request.form["name"])   # SQLi via Student.create: must be reported
    return "ok"
