import logging
import subprocess
import sys

import click
import requests


@click.command()
@click.argument("url")
@click.argument("username")
def http_brute(url, username):
    # the operator of this CLI chooses url/username on their own machine: not an attacker-controlled (remote) source
    response = requests.post(url, data={"username": username})
    logging.info("%s %s", username, response.status_code)


def main():
    program = sys.argv[1]
    subprocess.run([program, "--version"])      # local CLI argument, same trust as the shell running it


if __name__ == "__main__":
    http_brute()
