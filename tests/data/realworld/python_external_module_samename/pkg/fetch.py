import json
import urllib.request

from pkg import store


def fetch(url):
    with urllib.request.urlopen(url) as resp:
        return json.load(resp)


def fetch_and_store(url):
    with urllib.request.urlopen(url) as resp:
        return store.load(resp.read().decode())
