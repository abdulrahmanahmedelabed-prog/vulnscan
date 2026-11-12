import pickle
import subprocess

from celery import Celery

app = Celery("tasks", broker="redis://localhost")


@app.task
def add(x, y):
    return x + y                     # a task result goes to the result backend, not an HTTP response: no DF013


@app.task
def run(cmd):
    subprocess.run(cmd, shell=True)  # task arguments come from the broker: a DF002/DF003 here is reasonable


def roundtrip(obj):
    return pickle.loads(pickle.dumps(obj))   # bytes produced by the program itself: not untrusted deserialization


W_CERT = """Setting ssl_cert_reqs=CERT_NONE disables certificate checks."""   # prose in a warning string
