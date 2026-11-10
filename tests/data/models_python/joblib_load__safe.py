# expect-none: DF006
import joblib
from flask import Flask, request

app = Flask(__name__)


@app.post("/model")
def model():
    request.files["m"]
    return str(joblib.load("/srv/models/default.joblib"))
