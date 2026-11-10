# expect: DF013
from django.http import HttpResponse


def echo(request):
    return HttpResponse(content="<p>" + request.GET["q"] + "</p>")
