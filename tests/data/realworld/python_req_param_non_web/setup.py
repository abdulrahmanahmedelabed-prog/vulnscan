import os


def _pip_requirement(req):
    if req.startswith("-r "):
        _, path = req.split()
        return reqs(*path.split("/"))
    return [req]


def _reqs(*f):
    return [_pip_requirement(r) for r in (
        line.strip() for line in open(os.path.join(os.getcwd(), "requirements", *f)).readlines()) if r]


def reqs(*f):
    return [req for subreq in _reqs(*f) for req in subreq]
