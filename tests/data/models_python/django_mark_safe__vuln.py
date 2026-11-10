# expect: DF013
from django.shortcuts import render
from django.utils.safestring import mark_safe


def greet(request):
    name = request.GET.get("name", "")
    return render(request, "greet.html", {"msg": mark_safe("<b>" + name + "</b>")})
