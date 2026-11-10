# expect: DF008
from django.http import HttpResponsePermanentRedirect


def go(request):
    return HttpResponsePermanentRedirect(request.GET["next"])
