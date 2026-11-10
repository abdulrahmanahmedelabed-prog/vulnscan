# expect: DF007
import tornado.template
import tornado.web


class Page(tornado.web.RequestHandler):
    def get(self):
        t = tornado.template.Template("<p>" + self.get_query_argument("t") + "</p>")
        self.finish(t.generate())
