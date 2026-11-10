# expect-none: DF014
import ldap
from ldap.filter import escape_filter_chars
from flask import Flask, request

app = Flask(__name__)


@app.route("/l")
def l():
    conn = ldap.initialize("ldap://dir")
    return str(conn.search(base="dc=x", scope=ldap.SCOPE_SUBTREE, filterstr="(uid=" + escape_filter_chars(request.args["u"]) + ")"))
