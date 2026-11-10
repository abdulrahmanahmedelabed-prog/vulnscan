# expect: DF003
import subprocess
from fastapi import APIRouter, Header

router = APIRouter()


@router.api_route("/ping", methods=["GET", "POST"])
def ping(host: str = Header(...)):
    return subprocess.check_output("ping -c 1 " + host, shell=True)
