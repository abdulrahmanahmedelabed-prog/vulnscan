import pickle
import subprocess

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.views import View
from rest_framework import viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny

from .models import Product


def home(request):
    return HttpResponse("home")


def search(request):
    term = request.GET.get("q")
    with connection.cursor() as cur:
        cur.execute("SELECT id, name FROM shop_product WHERE name LIKE '%" + term + "%'")
        return JsonResponse({"rows": cur.fetchall()})


def report(request, year):
    return HttpResponse(str(year))


class ExportView(LoginRequiredMixin, View):
    def get(self, request, fmt):
        out = subprocess.run("export-tool --format " + fmt, shell=True, capture_output=True)
        return HttpResponse(out.stdout)

    def post(self, request, fmt):
        return HttpResponse(pickle.loads(request.body))


class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all()

    @action(detail=True, methods=["post"], permission_classes=[AllowAny])
    def restock(self, request, pk=None):
        return JsonResponse({"amount": request.data.get("amount")})


@api_view(["GET", "POST"])
@permission_classes([AllowAny])
def stock(request):
    return JsonResponse({"sku": request.query_params.get("sku")})
