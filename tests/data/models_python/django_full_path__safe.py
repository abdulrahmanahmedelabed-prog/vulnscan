# expect-none: DF008
from django.shortcuts import redirect


def go(request):
    request.get_full_path()
    return redirect("/login")
