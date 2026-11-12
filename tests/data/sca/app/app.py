import requests
import yaml as y
from jinja2 import Environment


def load(text):
    return y.load(text)


def render(src):
    return Environment().from_string(src).render()


def fetch(url):
    return requests.get(url)
