import subprocess
import tornado.web

class ExecHandler(tornado.web.RequestHandler):
    def get(self):
        args = self.get_argument("args")
        cmd = ["sh", "-c", "ls " + args]
        out = subprocess.check_output(cmd)
        self.write(out)
