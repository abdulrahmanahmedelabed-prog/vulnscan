# expect: DF006
import joblib
from flask import Flask, request

app = Flask(__name__)


@app.post("/model")
def model():
    return str(joblib.load(request.files["m"]))
