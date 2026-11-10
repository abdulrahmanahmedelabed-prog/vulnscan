# expect-none: DF008
from pyramid.httpexceptions import HTTPFound


def login(request):
    request.params["came_from"]
    return HTTPFound(location="/home")
