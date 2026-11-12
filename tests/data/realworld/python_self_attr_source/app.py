import os


class Parser:
    def __init__(self, stream):
        self.stream = stream

    def parse(self):
        node = next(self.stream)
        os.system(node)          # FP expected-not-reported: self.stream is not request.stream


class Signature:
    def __init__(self, arguments):
        self.arguments = arguments

    def run(self):
        for name in self.arguments:
            eval(name)           # FP expected-not-reported: self.arguments is not tornado request.arguments
