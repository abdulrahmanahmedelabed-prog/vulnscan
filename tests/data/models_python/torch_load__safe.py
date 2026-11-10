# expect-none: DF006
import torch
from fastapi import FastAPI

app = FastAPI()


@app.post("/w")
def w(path: str):
    return str(torch.load("/srv/models/base.pt"))
