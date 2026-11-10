# expect: DF004
from fastapi import FastAPI, Query
from sqlalchemy import text

app = FastAPI()


@app.get("/items")
def items(db, q: str = Query(...)):
    return db.execute(text("SELECT * FROM items WHERE name = '" + q + "'")).all()
