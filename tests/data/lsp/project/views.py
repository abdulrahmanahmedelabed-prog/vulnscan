from flask import Flask, request

from helpers import run_backup, run_backup_safely

app = Flask(__name__)


@app.route("/backup")
def backup():
    name = request.args.get("name", "")
    run_backup(name)
    return "ok"


@app.route("/backup-safe")
def backup_safe():
    name = request.args.get("name", "")
    run_backup_safely(name)
    return "ok"
