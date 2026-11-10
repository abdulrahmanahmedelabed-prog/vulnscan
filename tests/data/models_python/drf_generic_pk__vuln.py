# expect: DF004
from django.db import connection
from rest_framework.generics import RetrieveAPIView
from rest_framework.response import Response


class Detail(RetrieveAPIView):
    def retrieve(self, request, pk):
        cur = connection.cursor()
        cur.execute("SELECT * FROM t WHERE id = " + pk)
        return Response({})
