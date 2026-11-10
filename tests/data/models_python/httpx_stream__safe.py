# expect-none: DF010
import httpx
from fastapi import FastAPI

app = FastAPI()


@app.get("/p")
def p(u: str):
    with httpx.stream("GET", "https://api.example.com/", params={"q": u}) as r:
        return r.status_code
