from fastapi import FastAPI, Header
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.get("/items/")
async def read_items(user_agent: str | None = Header(default=None)):
    return {"User-Agent": user_agent}                     # FastAPI serialises to application/json: not XSS


@app.get("/page/", response_class=HTMLResponse)
async def page(q: str = ""):
    return "<p>" + q + "</p>"                              # true positive: HTML response with user input
