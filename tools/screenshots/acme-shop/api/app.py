import os
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, jsonify, request, send_file
from flask_login import login_required

app = Flask(__name__)
db = sqlite3.connect("shop.db", check_same_thread=False)
REPORTS_DIR = "/srv/reports"


def order_query(table, customer):
    return "SELECT * FROM " + table + " WHERE customer = '" + customer + "'"


@app.route("/orders")
def orders():
    customer = request.args.get("customer", "")
    rows = db.execute(order_query("orders", customer)).fetchall()
    return jsonify(rows)


@app.route("/reports/<name>")
def report(name):
    return send_file(os.path.join(REPORTS_DIR, name))


@app.route("/preview")
def preview():
    url = request.args["url"]
    return requests.get(url, timeout=5).text


@app.route("/admin/backup", methods=["POST"])
@login_required
def backup():
    target = request.form["target"]
    subprocess.run("tar czf /backups/" + target + ".tgz /srv/data", shell=True, check=True)
    return "ok"


@app.route("/import", methods=["POST"])
@login_required
def import_catalog():
    catalog = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify(count=len(catalog))


@app.route("/health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
