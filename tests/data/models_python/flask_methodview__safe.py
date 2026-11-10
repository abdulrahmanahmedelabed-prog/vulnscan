# expect-none: DF004
import sqlite3
from flask.views import MethodView


class Users(MethodView):
    def get(self, name):
        db = sqlite3.connect("app.db")
        return str(db.execute("SELECT * FROM u WHERE n = ?", (name,)).fetchall())
