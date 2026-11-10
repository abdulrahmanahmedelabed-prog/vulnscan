# expect-none: DF011
import boto3
from flask import Flask, request

app = Flask(__name__)
bucket = boto3.resource("s3").Bucket("reports")


@app.route("/r")
def r():
    # the Key is chosen by the user, the local path is fixed: S3 keys are a flat namespace, not a file path
    bucket.download_file("public/" + request.args["name"], "/tmp/report.csv")
    return "ok"
