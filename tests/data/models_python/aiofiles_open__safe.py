# expect-none: DF005
import os
import aiofiles
from fastapi import FastAPI

app = FastAPI()


@app.get("/r")
async def r(name: str):
    async with aiofiles.open("/srv/" + os.path.basename(name)) as fh:
        return await fh.read()
