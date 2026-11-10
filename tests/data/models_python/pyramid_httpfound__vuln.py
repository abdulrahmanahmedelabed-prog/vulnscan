# expect: DF008
from pyramid.httpexceptions import HTTPFound


def login(request):
    return HTTPFound(location=request.params["came_from"])
