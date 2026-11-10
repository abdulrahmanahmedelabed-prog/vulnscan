# expect: DF013
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.get("/hi")
def hi(name: str):
    return HTMLResponse(content="<h1>" + name + "</h1>")
