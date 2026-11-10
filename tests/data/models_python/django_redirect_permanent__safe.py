# expect-none: DF008
from django.http import HttpResponsePermanentRedirect
from django.utils.http import url_has_allowed_host_and_scheme


def go(request):
    nxt = request.GET["next"]
    if url_has_allowed_host_and_scheme(nxt, allowed_hosts={"example.com"}):
        return HttpResponsePermanentRedirect(nxt)
    return HttpResponsePermanentRedirect("/")
