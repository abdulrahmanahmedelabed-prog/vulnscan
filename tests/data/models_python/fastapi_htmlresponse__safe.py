# expect-none: DF013
import html
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.get("/hi")
def hi(name: str):
    return HTMLResponse(content="<h1>" + html.escape(name) + "</h1>")
