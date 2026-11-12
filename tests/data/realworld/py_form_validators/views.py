import os
from django import forms
from django.http import HttpResponse
from django.db import connection


class SearchForm(forms.Form):
    age = forms.IntegerField()
    name = forms.CharField()


def search(request, slug):
    form = SearchForm(request.GET)
    if form.is_valid():
        cur = connection.cursor()
        cur.execute("SELECT * FROM p WHERE age = %s" % form.cleaned_data["age"])      # safe: IntegerField
        cur.execute("SELECT * FROM p WHERE name = '%s'" % form.cleaned_data["name"])  # vuln: CharField
    return HttpResponse("ok")
