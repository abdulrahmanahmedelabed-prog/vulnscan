# expect-none: DF002
import asyncio
import shlex
from fastapi import FastAPI

app = FastAPI()


@app.get("/p")
async def p(host: str):
    loop = asyncio.get_running_loop()
    await loop.subprocess_shell(asyncio.SubprocessProtocol, "ping " + shlex.quote(host))
