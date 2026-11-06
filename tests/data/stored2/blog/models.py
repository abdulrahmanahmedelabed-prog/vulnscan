from django.db import models

class Post(models.Model):
    body = models.TextField()

class Tag(models.Model):
    label = models.CharField(max_length=20)
    class Meta:
        db_table = "custom_tags"
