# expect-none: DF008
from aiohttp import web


async def go(request):
    request.query["next"]
    raise web.HTTPFound("/")
