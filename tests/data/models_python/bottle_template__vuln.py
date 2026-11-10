# expect: DF007
from bottle import get, request, template


@get("/t")
def page():
    return template("<p>" + request.query.get("x") + "</p>")
