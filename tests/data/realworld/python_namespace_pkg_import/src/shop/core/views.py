# src layout without __init__.py files: the module is `src.shop.core.helpers`, imported as `shop.core.helpers`
import json

import shop.core.helpers
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run_view():
    shop.core.helpers.run(request.args.get("c"))
    return "ok"


@app.route("/load")
def load_view():
    data = json.loads(request.args.get("d"))
    return {"n": len(data)}
