import os

from fastapi import APIRouter, Cookie, UploadFile
from pydantic import BaseModel

router = APIRouter()


class Item(BaseModel):
    name: str
    path: str


@router.get("/{item_id}")
def read_item(item_id: int, q: str = None, session_id: str = Cookie(None)):
    return {"id": item_id, "q": q}


@router.post("/")
def create_item(item: Item):
    with open(os.path.join("/data/items", item.path), "w") as fh:
        fh.write(item.name)
    return item


@router.post("/{item_id}/image")
def upload(item_id: int, image: UploadFile):
    return {"name": image.filename}
