# expect-none: DF004
from django.http import HttpResponse
from .models import User


def search(request):
    name = request.GET.get("name")
    users = User.objects.raw("SELECT * FROM users WHERE name = %s", [name])
    return HttpResponse(str(len(list(users))))
