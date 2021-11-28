import click
import os
import errno
import applepy.globals
from datetime import datetime


def save_to_log(data):
    filename = "logs/" + str(applepy.globals.TIME)
    if not os.path.exists(os.path.dirname(filename)):
        try:
            os.makedirs(os.path.dirname(filename))
        except OSError as exc:  # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise
    print("log: " + str(data))
    with open(filename, "a+") as log:
        log.write(str(datetime.now()) + " > " + str(data) + "\n")


def echo(text, nl=False):
    click.echo(text, nl=nl)
    save_to_log(text)
