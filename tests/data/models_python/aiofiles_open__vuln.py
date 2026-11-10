# expect: DF005
import aiofiles
from fastapi import FastAPI

app = FastAPI()


@app.get("/r")
async def r(name: str):
    async with aiofiles.open("/srv/" + name) as fh:
        return await fh.read()
