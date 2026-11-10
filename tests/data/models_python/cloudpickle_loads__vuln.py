# expect: DF006
import cloudpickle
from flask import Flask, request

app = Flask(__name__)


@app.post("/job")
def job():
    return str(cloudpickle.loads(request.get_data()))
