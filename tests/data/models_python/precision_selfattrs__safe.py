# expect-none: DF002 DF004 DF005 DF011
import os
import sqlite3


class Report:
    def __init__(self):
        self.params = {"dir": "/srv/reports"}
        self.forms = ["a"]
        self.matchdict = {}

    def build(self):
        os.listdir(self.params["dir"])
        sqlite3.connect("r.db").execute("SELECT count(*) FROM " + self.forms[0])
