# expect: DF013
from sanic import Sanic, response

app = Sanic("a")


@app.get("/hi")
async def hi(request):
    return response.html("<b>" + request.args.get("n") + "</b>")
