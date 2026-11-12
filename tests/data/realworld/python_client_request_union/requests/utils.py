from __future__ import annotations

import urllib.request

from .models import PreparedRequest, Request


def resolve(request: Request | PreparedRequest):
    # an outbound client request object built by the library itself, not an inbound HTTP request
    return urllib.request.urlopen(request.url)
