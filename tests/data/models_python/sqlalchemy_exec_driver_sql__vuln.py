# expect: DF004
from flask import Flask, request
from sqlalchemy import create_engine

app = Flask(__name__)
engine = create_engine("sqlite://")


@app.route("/q")
def q():
    with engine.connect() as conn:
        return str(conn.exec_driver_sql("SELECT * FROM t WHERE c = '" + request.args["c"] + "'").all())
