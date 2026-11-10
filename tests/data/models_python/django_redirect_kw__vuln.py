# expect: DF008
from django.http import HttpResponseRedirect


def go(request):
    return HttpResponseRedirect(redirect_to=request.GET["next"])
