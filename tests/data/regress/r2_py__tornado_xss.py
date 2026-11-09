import tornado.web

class HelloHandler(tornado.web.RequestHandler):
    def get(self):
        name = self.get_query_argument("name")
        self.write("<html><body>Hi " + name + "</body></html>")
