# expect-none: DF011
import os
import boto3
from flask import Flask, request

app = Flask(__name__)
s3 = boto3.client("s3")


@app.post("/backup")
def backup():
    s3.upload_file("/srv/exports/" + os.path.basename(request.form["name"]), "backups", "latest.csv")
    return "ok"
