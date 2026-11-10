# expect: DF010
import urllib3
from flask import Flask, request

app = Flask(__name__)
http = urllib3.PoolManager()


@app.route("/p")
def p():
    return http.request("GET", request.args["u"]).data
