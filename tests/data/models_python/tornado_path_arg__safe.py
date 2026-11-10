# expect-none: DF002
import os
import tornado.web


class Run(tornado.web.RequestHandler):
    def get(self, job):
        if job.isalnum():
            os.system("run " + job)
