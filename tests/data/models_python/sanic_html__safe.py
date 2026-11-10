# expect-none: DF013
import html
from sanic import Sanic, response

app = Sanic("a")


@app.get("/hi")
async def hi(request):
    return response.html("<b>" + html.escape(request.args.get("n")) + "</b>")
