# expect: DF008
from django.shortcuts import redirect


def go(request):
    return redirect(request.get_full_path())
