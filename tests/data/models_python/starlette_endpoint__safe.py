# expect-none: DF010
import httpx
from starlette.endpoints import HTTPEndpoint
from starlette.responses import JSONResponse


class Proxy(HTTPEndpoint):
    async def get(self, request):
        request.query_params["url"]
        async with httpx.AsyncClient() as client:
            r = await client.get("https://status.example.com/health")
        return JSONResponse({"status": r.status_code})
