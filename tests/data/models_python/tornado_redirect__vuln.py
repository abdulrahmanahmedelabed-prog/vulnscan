# expect: DF008
import tornado.web


class Go(tornado.web.RequestHandler):
    def get(self):
        self.redirect(self.get_argument("next"))
