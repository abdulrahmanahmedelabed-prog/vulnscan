# expect: DF002
import os
from starlette.responses import PlainTextResponse


async def handler(request):
    os.system("echo " + request.url.query)
    return PlainTextResponse("ok")
