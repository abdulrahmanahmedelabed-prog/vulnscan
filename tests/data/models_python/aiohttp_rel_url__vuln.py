# expect: DF005
from aiohttp import web


async def dl(request):
    name = request.rel_url.query["f"]
    with open("/srv/" + name) as fh:
        return web.Response(text=fh.read())
