# expect-none: DF011
import os
import boto3
from flask import Flask, request

app = Flask(__name__)
s3 = boto3.client("s3")


@app.route("/s3")
def get_obj():
    s3.download_file("reports", "daily.csv", "/tmp/" + os.path.basename(request.args["name"]))
    return "ok"
