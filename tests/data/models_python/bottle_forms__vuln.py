# expect: DF003
import subprocess
from bottle import post, request


@post("/run")
def run_cmd():
    subprocess.call(request.forms.get("cmd"), shell=True)
