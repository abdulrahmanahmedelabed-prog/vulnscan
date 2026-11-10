# expect: DF010
import aiohttp
from aiohttp import web


async def fetch(request):
    url = request.query["url"]
    async with aiohttp.ClientSession() as session:
        async with session.request("GET", url) as r:
            return web.json_response({"s": r.status})
