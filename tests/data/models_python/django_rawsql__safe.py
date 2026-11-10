# expect-none: DF004
from django.db.models.expressions import RawSQL
from django.http import JsonResponse
from .models import Item


def view(request):
    col = request.POST["col"]
    qs = Item.objects.annotate(v=RawSQL("SELECT val FROM t WHERE k = %s", (col,)))
    return JsonResponse({"n": qs.count()})
