# expect-none: DF012
import pydoc
from flask import Flask, request

app = Flask(__name__)
PLUGINS = ("app.export.CsvExporter", "app.export.JsonExporter")


@app.route("/plugin")
def plugin():
    name = request.args["cls"]
    if name not in PLUGINS:
        return "unknown", 400
    return str(pydoc.locate(name))
