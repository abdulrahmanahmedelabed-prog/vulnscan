import requests
from flask import Flask, request
app = Flask(__name__)
base = "https://api.example.com/"
@app.route('/p')
def p():
    base = request.args['u']
    return requests.get(base + "/v1/items").text
