import os, subprocess, pickle, sqlite3
from flask import Flask, request
app = Flask(__name__)
@app.route("/a", methods=["POST"])
def a():
    data = request.get_json()
    os.system(data["c"])
    subprocess.run(data["c"], shell=True)
    db = sqlite3.connect("x")
    db.execute(f"SELECT * FROM u WHERE n='{data['n']}'")
    pickle.loads(request.get_data())
    eval(request.get_json()["e"])
    raw = request.get_data(as_text=True)
    exec(raw)
