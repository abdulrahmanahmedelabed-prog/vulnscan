# expect: DF006
import io
import pickle
from flask import Flask, request

app = Flask(__name__)


@app.post("/p")
def p():
    return str(pickle.Unpickler(io.BytesIO(request.data)).load())
