from django.contrib.auth.decorators import login_required
from django.urls import include, path

from shop import views

urlpatterns = [
    path("", views.home),
    path("shop/", include("shop.urls")),
    path("reports/<int:year>/", login_required(views.report), name="report"),
]
