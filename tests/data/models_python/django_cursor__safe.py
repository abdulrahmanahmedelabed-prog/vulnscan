# expect-none: DF004
from django.db import connection
from django.http import JsonResponse


def view(request, user_id):
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM sessions WHERE uid = %s", [user_id])
    return JsonResponse({})
