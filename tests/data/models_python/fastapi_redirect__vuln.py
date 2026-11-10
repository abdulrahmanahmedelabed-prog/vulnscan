# expect: DF008
from fastapi import FastAPI
from fastapi.responses import RedirectResponse

app = FastAPI()


@app.get("/go")
def go(next: str):
    return RedirectResponse(url=next)
