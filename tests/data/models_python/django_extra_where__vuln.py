# expect: DF004
from django.http import JsonResponse
from .models import User


def search(request):
    name = request.GET["name"]
    qs = User.objects.extra(where=["name = '%s'" % name])
    return JsonResponse({"n": qs.count()})
