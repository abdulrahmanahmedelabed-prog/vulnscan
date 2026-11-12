from django.utils.module_loading import import_string

BACKEND_SESSION_KEY = "_auth_user_backend"


class RemoteUserMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        backend_str = request.session[BACKEND_SESSION_KEY]
        backend = import_string(backend_str)                  # server-side session state: not a finding
        user = request.user
        other = import_string(user.backend_path)              # the authenticated user record: not a finding
        chosen = import_string(request.GET.get("backend"))    # client input: reported
        return self.get_response(request), backend, other, chosen
