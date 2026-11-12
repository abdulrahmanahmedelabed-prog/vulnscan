from django.db import models


class Lab(models.Model):
    name = models.CharField(max_length=100)
