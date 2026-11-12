import os
from flask import Flask
from flask_wtf import FlaskForm
from wtforms import IntegerField, StringField
from wtforms.validators import Regexp

app = Flask(__name__)


class F(FlaskForm):
    n = IntegerField()
    host = StringField(validators=[Regexp(r"^[a-z0-9.]+$")])
    cmd = StringField()


@app.route("/w", methods=["POST"])
def w():
    form = F()
    if form.validate_on_submit():
        os.system("ping " + form.host.data)    # safe: strict Regexp
        os.system(form.cmd.data)               # vuln
    return "x"
