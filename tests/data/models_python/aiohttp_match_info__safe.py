# expect-none: DF004
from aiohttp import web

routes = web.RouteTableDef()


@routes.get("/u/{name}")
async def user(request):
    name = request.match_info["name"]
    rows = await request.app["db"].fetch("SELECT * FROM u WHERE name = $1", name)
    return web.json_response([dict(r) for r in rows])
