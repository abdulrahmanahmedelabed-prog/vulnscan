# expect-none: DF006
import json
from flask import Flask, request

app = Flask(__name__)


@app.post("/job")
def job():
    return str(json.loads(request.get_data()))
