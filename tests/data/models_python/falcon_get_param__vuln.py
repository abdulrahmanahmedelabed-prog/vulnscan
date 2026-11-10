# expect: DF002
import os


class Resource:
    def on_get(self, req, resp):
        os.system("lookup " + req.get_param("host"))
