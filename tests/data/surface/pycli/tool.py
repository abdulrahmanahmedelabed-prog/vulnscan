import os

import click
from celery import Celery

queue = Celery("tool")


@click.command()
@click.option("--target")
@click.argument("archive")
def extract(target, archive):
    os.system("tar -xf " + archive + " -C " + target)


@queue.task
def resize(path, width):
    os.system("convert " + path + " -resize " + str(width) + " out.png")


if __name__ == "__main__":
    extract()
