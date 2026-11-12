import sqlite3
import subprocess

from flask import Flask, abort, redirect, render_template_string, request, session
from flask_login import login_required

from blueprints.admin import admin_bp

app = Flask(__name__)
app.register_blueprint(admin_bp, url_prefix="/admin")


def get_db():
    return sqlite3.connect("app.db")


def find_user(name):
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return cur.fetchall()


@app.route("/users")
def users():
    return {"rows": find_user(request.args.get("name"))}


@app.route("/greet/<name>")
def greet(name):
    return render_template_string("Hello " + name + request.headers.get("X-Suffix", ""))


@app.route("/ping", methods=["POST"])
@login_required
def ping():
    host = request.form["host"]
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/go")
def go():
    return redirect(request.args["next"])


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        abort(401)
    data = request.get_json()
    return {"name": data["display_name"], "theme": request.cookies.get("theme")}


@app.cli.command("purge")
def purge():
    get_db().execute("DELETE FROM sessions")
