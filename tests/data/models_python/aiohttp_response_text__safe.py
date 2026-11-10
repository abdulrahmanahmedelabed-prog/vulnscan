# expect-none: DF013
import html
from aiohttp import web


async def hello(request):
    return web.Response(text="<h1>" + html.escape(request.query["name"]) + "</h1>", content_type="text/html")
