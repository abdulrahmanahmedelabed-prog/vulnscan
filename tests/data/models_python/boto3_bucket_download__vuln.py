# expect: DF011
import boto3
from flask import Flask, request

app = Flask(__name__)
bucket = boto3.resource("s3").Bucket("reports")


@app.route("/r")
def r():
    bucket.download_file("daily.csv", Filename="/tmp/" + request.args["name"])
    return "ok"
