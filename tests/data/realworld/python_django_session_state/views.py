from django.http import HttpResponse
from django.utils.module_loading import import_string


def get_exception_response(request, resolver, status_code, exception):
    callback = import_string("handlers.handler%s" % status_code)    # a helper called below: not a view
    return callback(request, exception=exception)


def response_for_exception(request):
    return get_exception_response(request, None, 404, None)


def plugin(request, name):
    handler = import_string(name)                         # a view: `name` is captured from the URL
    return HttpResponse(handler())
