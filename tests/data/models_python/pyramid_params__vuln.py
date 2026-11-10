# expect: DF002
import os


def view(request):
    os.system("convert " + request.params["img"])
    return {}
