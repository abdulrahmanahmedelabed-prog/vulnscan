# expect-none: DF003
import subprocess
from bottle import post, request


@post("/run")
def run_cmd():
    subprocess.call(["/usr/bin/report", "--id", request.forms.get("cmd")])
