# expect-none: DF004
from flask import Flask, request
from .models import User

app = Flask(__name__)


@app.route("/s")
def s():
    return str(User.objects.where("this.age > " + str(int(request.args["age"]))).count())
