# expect: DF005
from fastapi import FastAPI, File, UploadFile

app = FastAPI()


@app.post("/up")
async def up(file: UploadFile = File(...)):  # noqa: B008 - FastAPI dependency default
    with open("/srv/up/" + file.filename, "wb") as out:
        out.write(await file.read())
