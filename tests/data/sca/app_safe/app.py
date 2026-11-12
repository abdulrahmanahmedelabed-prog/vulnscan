import json

import requests
import yaml


def load(text):
    return yaml.safe_load(text)


def other(fh):
    return json.load(fh)


def fetch(url):
    return requests.get(url)
