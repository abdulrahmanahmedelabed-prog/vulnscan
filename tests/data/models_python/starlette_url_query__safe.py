# expect-none: DF002
import os
import shlex
from starlette.responses import PlainTextResponse


async def handler(request):
    os.system("echo " + shlex.quote(request.url.query))
    return PlainTextResponse("ok")
