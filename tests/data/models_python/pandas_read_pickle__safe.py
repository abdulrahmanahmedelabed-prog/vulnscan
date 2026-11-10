# expect-none: DF006
import pandas as pd
from flask import Flask, request

app = Flask(__name__)


@app.post("/df")
def df():
    return pd.read_json(request.files["f"]).to_json()
