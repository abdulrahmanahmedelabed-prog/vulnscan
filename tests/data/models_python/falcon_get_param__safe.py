# expect-none: DF002
import os
import shlex


class Resource:
    def on_get(self, req, resp):
        os.system("lookup " + shlex.quote(req.get_param("host")))
