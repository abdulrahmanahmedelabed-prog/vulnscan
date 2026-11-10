# expect-none: DF006
import io
import json
from flask import Flask, request

app = Flask(__name__)


@app.post("/p")
def p():
    return str(json.load(io.BytesIO(request.data)))
