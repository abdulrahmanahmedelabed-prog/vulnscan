# expect: DF004
import asyncpg
from fastapi import FastAPI

app = FastAPI()


@app.get("/u")
async def u(name: str):
    conn = await asyncpg.connect()
    return await conn.fetchrow("SELECT * FROM u WHERE n = '" + name + "'")
