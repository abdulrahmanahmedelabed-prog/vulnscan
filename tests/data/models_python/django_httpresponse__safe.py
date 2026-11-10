# expect-none: DF013
from django.http import HttpResponse
from django.utils.html import escape


def echo(request):
    return HttpResponse(content="<p>" + escape(request.GET["q"]) + "</p>")
