# expect: DF004
from flask import Flask, request
from sqlalchemy.sql.expression import text

app = Flask(__name__)


@app.route("/q")
def q():
    stmt = text("SELECT * FROM t ORDER BY " + request.args["order"])
    return str(stmt)
