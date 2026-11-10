# expect-none: DF007
from bottle import get, request, template


@get("/t")
def page():
    return template("<p>{{x}}</p>", x=request.query.get("x"))
