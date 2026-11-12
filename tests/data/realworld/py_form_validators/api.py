import os
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class Item(BaseModel):
    count: int
    path: str


@app.get("/a")
def a(n: int, name: str):
    os.system("echo %d" % n)          # safe: int parameter
    os.system("echo " + name)         # vuln: str parameter
    return "x"


@app.post("/b")
def b(item: Item):
    os.system("ls %d" % item.count)   # safe
    os.system("ls " + item.path)      # vuln
    return "x"
