# expect: DF015
from flask import Flask, request
from lxml import etree

app = Flask(__name__)
doc = etree.parse("users.xml")


@app.route("/x")
def x():
    return str(doc.xpath("//user[@name='" + request.args["n"] + "']"))
