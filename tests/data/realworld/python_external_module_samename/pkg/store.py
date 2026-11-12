import json
import pathlib


def load(path):
    p = pathlib.Path(path)
    return json.loads(p.read_text())
