import logging

from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.route("/log")
def log():
    q = request.args.get("q")
    getattr(logger, "info")("searched %s", q)          # the message argument is not the attribute name
    return "ok"


@app.route("/log_level")
def log_level():
    level = request.args.get("level")
    getattr(logger, level)("searched")                  # the caller picks the method: reported
    return "ok"
