# expect-none: DF010
import aiohttp
from fastapi import FastAPI

app = FastAPI()


@app.get("/p")
async def p(u: str):
    async with aiohttp.request("GET", "https://api.example.com/", params={"q": u}) as r:
        return r.status
