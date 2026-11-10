# expect: DF005
from fastapi import FastAPI
from fastapi.responses import FileResponse

app = FastAPI()


@app.get("/f/{name}")
def get_file(name: str):
    return FileResponse("/srv/static/" + name)
