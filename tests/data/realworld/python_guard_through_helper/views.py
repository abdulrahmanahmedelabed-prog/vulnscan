from django.http import HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme


def translate(url, code):
    return url.replace("/en/", "/" + code + "/")


def set_language(request):
    next_url = request.POST.get("next")
    if not url_has_allowed_host_and_scheme(url=next_url, allowed_hosts={request.get_host()}):
        next_url = "/"
    response = HttpResponseRedirect(next_url)
    nt = translate(next_url, "ar")
    if nt != next_url:
        response = HttpResponseRedirect(nt)
    return response


def set_language2(request):
    next_url = request.POST.get("next")
    if not url_has_allowed_host_and_scheme(url=next_url, allowed_hosts={request.get_host()}):
        next_url = request.META.get("HTTP_REFERER")
        if not url_has_allowed_host_and_scheme(url=next_url, allowed_hosts={request.get_host()}):
            next_url = "/"
    return HttpResponseRedirect(next_url)


def set_language3(request):
    next_url = request.POST.get("next")
    nt = translate(next_url, "ar")
    if not url_has_allowed_host_and_scheme(url=next_url, allowed_hosts={request.get_host()}):
        next_url = "/"
    return HttpResponseRedirect(nt)


def set_language4(request):
    next_url = request.POST.get("next")
    other = request.GET.get("o")
    if not url_has_allowed_host_and_scheme(url=next_url, allowed_hosts={request.get_host()}):
        next_url = "/"
    nt = translate(next_url, other)
    return HttpResponseRedirect(nt)
