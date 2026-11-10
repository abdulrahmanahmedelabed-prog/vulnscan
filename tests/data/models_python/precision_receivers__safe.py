# expect-none: DF004 DF011
import imaplib
import boto3
from flask import Flask, request

app = Flask(__name__)
s3 = boto3.client("s3")


class Avatar:
    def extract(self, member, size):
        return member, size


class Context:
    def fetch(self, key):
        return key


avatar = Avatar()


@app.route("/p")
def p():
    q = request.args["q"]
    imap_conn = imaplib.IMAP4_SSL("mail.example.com")
    imap_conn.fetch(q, "(RFC822)")                     # IMAP message set, not SQL
    ctx = Context()
    ctx.fetch(q)
    avatar.extract("face", q)                          # not an archive
    body = s3.get_object(Bucket="docs", Key="public/" + q)["Body"].read()   # S3 key: flat namespace, not a path
    return body
