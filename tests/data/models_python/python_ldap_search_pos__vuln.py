# expect: DF014
import ldap
from flask import Flask, request

app = Flask(__name__)


@app.route("/l")
def l():
    conn = ldap.initialize("ldap://dir")
    return str(conn.search_ext("dc=x", ldap.SCOPE_SUBTREE, "(uid=" + request.args["u"] + ")"))
