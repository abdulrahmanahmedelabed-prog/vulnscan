# expect: DF005
from sanic import Sanic
from sanic.response import file

app = Sanic("a")


@app.get("/f/<name>")
async def get_file(request, name):
    return await file("/srv/" + name)
