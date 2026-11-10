# expect: DF002
import os
from rest_framework import viewsets
from rest_framework.response import Response


class JobViewSet(viewsets.ModelViewSet):
    def create(self, request):
        os.system("run-job " + request.data["name"])
        return Response({})
