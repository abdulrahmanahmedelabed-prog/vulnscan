# expect-none: DF004
from pyramid.view import view_config


@view_config(route_name="user", renderer="json")
def user(context, req2):
    return {"r": context.db.execute("SELECT * FROM u WHERE id = :id", {"id": req2.matchdict["id"]}).fetchall()}
