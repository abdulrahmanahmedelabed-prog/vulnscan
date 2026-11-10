# expect-none: DF004 DF005 DF010 DF011
import pandas as pd
from flask import Flask, request
from .models import User

app = Flask(__name__)


class Cache:
    def fetch(self, key):
        return key


cache = Cache()


@app.route("/p")
def p():
    q = request.args["q"]
    col = pd.Series(["a1", "b2"]).str.extract(q)
    hit = cache.fetch(q)
    found = User.objects.filter(name=q).count()
    return {"c": len(col), "h": len(hit), "f": found}
