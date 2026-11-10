# expect: DF004
from flask import Flask, request
from sqlalchemy import literal_column, select

app = Flask(__name__)


@app.route("/q")
def q():
    return str(select(literal_column(request.args["col"])))
