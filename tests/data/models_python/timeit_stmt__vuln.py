# expect: DF001
import timeit
from flask import Flask, request

app = Flask(__name__)


@app.route("/bench")
def bench():
    return str(timeit.timeit(request.args["stmt"], number=1))
