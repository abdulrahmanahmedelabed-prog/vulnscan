# expect-none: DF004
from bson.code import Code
from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient().app


@app.route("/s")
def s():
    js = Code("this.name == name", {"name": request.args["n"]})
    return str(list(db.users.find({"$where": js})))
