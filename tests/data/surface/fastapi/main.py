import httpx
from fastapi import Depends, FastAPI, Header, Query

from routers import items
from security import get_current_user

app = FastAPI()
app.include_router(items.router, prefix="/items", dependencies=[Depends(get_current_user)])


@app.get("/fetch")
async def fetch(url: str, x_trace: str = Header(None)):
    async with httpx.AsyncClient() as client:
        resp = await client.get(url)
    return {"status": resp.status_code, "trace": x_trace}


@app.get("/me")
def me(user=Depends(get_current_user), verbose: bool = Query(False)):
    return user


@app.websocket("/ws")
async def ws(websocket):
    await websocket.accept()
