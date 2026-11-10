# expect: DF002
import os
import tornado.web


class Run(tornado.web.RequestHandler):
    def get(self, job):
        os.system("run " + job)
