# expect-none: DF008
from django.http import HttpResponseRedirect


def go(request):
    request.GET["next"]
    return HttpResponseRedirect(redirect_to="/home")
