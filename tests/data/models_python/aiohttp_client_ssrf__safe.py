# expect-none: DF010
import aiohttp
from aiohttp import web


async def fetch(request):
    request.query["url"]
    async with aiohttp.ClientSession() as session:
        async with session.request("GET", "https://api.example.com/") as r:
            return web.json_response({"s": r.status})
