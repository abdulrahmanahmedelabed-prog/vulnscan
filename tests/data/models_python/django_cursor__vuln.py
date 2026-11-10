# expect: DF004
from django.db import connection
from django.http import JsonResponse


def view(request, user_id):
    with connection.cursor() as cursor:
        cursor.execute(f"DELETE FROM sessions WHERE uid = {user_id}")
    return JsonResponse({})
