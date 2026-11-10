# expect: DF010
import httpx
from fastapi import FastAPI

app = FastAPI()


@app.get("/p")
def p(u: str):
    with httpx.stream("GET", u) as r:
        return r.status_code
