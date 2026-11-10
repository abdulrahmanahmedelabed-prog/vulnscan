# expect: DF008
from aiohttp import web


async def go(request):
    raise web.HTTPFound(request.query["next"])
