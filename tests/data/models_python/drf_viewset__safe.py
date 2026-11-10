# expect-none: DF002
import os
import shlex
from rest_framework import viewsets
from rest_framework.response import Response


class JobViewSet(viewsets.ModelViewSet):
    def create(self, request):
        os.system("run-job " + shlex.quote(request.data["name"]))
        return Response({})
