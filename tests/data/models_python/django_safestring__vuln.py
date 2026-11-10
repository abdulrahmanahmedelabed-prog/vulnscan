# expect: DF013
from django.shortcuts import render
from django.utils.safestring import SafeString


def greet(request):
    bio = request.POST["bio"]
    return render(request, "p.html", {"bio": SafeString(bio)})
