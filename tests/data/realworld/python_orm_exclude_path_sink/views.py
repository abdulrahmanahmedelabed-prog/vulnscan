from django.http import JsonResponse
from django.urls import path

from .models import Lab


def update_lab(request, lab_id):
    name = request.POST.get("name", "")
    if Lab.objects.filter(name=name).exclude(id=lab_id).exists():     # ORM query, not a filesystem path
        return JsonResponse({"status": "error"}, status=400)
    return JsonResponse({"status": "ok"})


urlpatterns = [path("labs/<int:lab_id>/", update_lab)]
