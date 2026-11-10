# expect-none: DF001
import timeit
from flask import Flask, request

app = Flask(__name__)


@app.route("/bench")
def bench():
    n = int(request.args["n"])
    return str(timeit.timeit("sum(range(100))", number=n))
