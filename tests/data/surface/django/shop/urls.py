from django.urls import include, path, re_path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r"products", views.ProductViewSet)

urlpatterns = [
    path("search/", views.search),
    re_path(r"^export/(?P<fmt>\w+)/$", views.ExportView.as_view()),
    path("api/", include(router.urls)),
    path("api/stock/", views.stock),
]
