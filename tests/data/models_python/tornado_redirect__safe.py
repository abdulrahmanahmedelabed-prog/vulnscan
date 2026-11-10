# expect-none: DF008
import tornado.web


class Go(tornado.web.RequestHandler):
    def get(self):
        self.get_argument("next")
        self.redirect("/")
