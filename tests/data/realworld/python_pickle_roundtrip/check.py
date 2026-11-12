import pickle

import requests


def response_is_pickleable(url):
    r = requests.get(url)
    pr = pickle.loads(pickle.dumps(r))      # deserialises bytes this program just produced: not CWE-502
    return pr.status_code


def load_remote(url):
    return pickle.loads(requests.get(url).content)   # true positive: remote bytes reach pickle.loads
