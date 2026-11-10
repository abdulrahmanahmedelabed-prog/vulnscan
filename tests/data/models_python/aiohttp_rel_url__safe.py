# expect-none: DF005
import os
from aiohttp import web


async def dl(request):
    name = request.rel_url.query["f"]
    with open("/srv/" + os.path.basename(name)) as fh:
        return web.json_response({"t": fh.read()})
