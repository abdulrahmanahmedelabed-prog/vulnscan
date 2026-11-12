import aiohttp_jinja2
from aiohttp import web
from aiohttp_jinja2 import template
from jinja2 import FileSystemLoader


@template("search.jinja2")
async def search(request: web.Request):
    q = request.query.get("q", "")
    return {"q": q}                                  # autoescape=False: {{ q }} is written raw


@template("search_escaped.jinja2")
async def search_escaped(request: web.Request):
    q = request.query.get("q", "")
    return {"q": q}                                  # the template prints {{ q|e }}: not a finding


@template("count.jinja2")
async def count(request: web.Request):
    n = int(request.query.get("n", "0"))
    return {"n": n}                                  # a number: not a finding


def init():
    app = web.Application()
    aiohttp_jinja2.setup(app, loader=FileSystemLoader("templates"), autoescape=False)
    app.router.add_get("/search", search)
    app.router.add_get("/search_escaped", search_escaped)
    app.router.add_get("/count", count)
    return app
