# expect-none: DF013
from django.shortcuts import render
from django.utils.html import format_html


def greet(request):
    name = request.GET.get("name", "")
    return render(request, "greet.html", {"msg": format_html("<b>{}</b>", name)})
