# expect: DF013
from aiohttp import web


async def hello(request):
    return web.Response(text="<h1>" + request.query["name"] + "</h1>", content_type="text/html")
