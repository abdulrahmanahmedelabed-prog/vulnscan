from flask import Flask, request
from sqlalchemy.orm import declarative_base, Session
from sqlalchemy import Column, String
import os
Base = declarative_base()
app = Flask(__name__)

class Item(Base):
    __tablename__ = "items"
    name = Column(String)
    tag = Column(String)

@app.route("/i", methods=["POST"])
def add():
    s = Session()
    it = Item(name=request.form["n"], tag="x")
    s.add(it)

@app.route("/i")
def show():
    s = Session()
    for it in s.query(Item).all():
        os.system(it.name)
        os.system(it.tag)
