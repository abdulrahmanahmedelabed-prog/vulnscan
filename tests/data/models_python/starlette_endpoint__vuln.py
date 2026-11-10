# expect: DF010
import httpx
from starlette.endpoints import HTTPEndpoint
from starlette.responses import JSONResponse


class Proxy(HTTPEndpoint):
    async def get(self, request):
        async with httpx.AsyncClient() as client:
            r = await client.get(request.query_params["url"])
        return JSONResponse({"status": r.status_code})
