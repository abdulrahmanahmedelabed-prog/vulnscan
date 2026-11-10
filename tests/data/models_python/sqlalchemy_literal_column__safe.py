# expect-none: DF004
from flask import Flask, request
from sqlalchemy import literal, select

app = Flask(__name__)


@app.route("/q")
def q():
    return str(select(literal(request.args["col"])))
