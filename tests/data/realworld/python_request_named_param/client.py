import urllib.request
from dataclasses import dataclass


@dataclass
class PreparedRequest:
    url: str
    body: bytes = b""


def send(request: PreparedRequest):
    # 'request' here is an outbound client request object built by the program, not an inbound HTTP request
    return urllib.request.urlopen(request.url)


def main():
    send(PreparedRequest("https://example.org/"))
