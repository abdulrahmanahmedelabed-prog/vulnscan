# expect-none: DF002
import os
import shlex


def view(request):
    os.system("convert " + shlex.quote(request.params["img"]))
    return {}
