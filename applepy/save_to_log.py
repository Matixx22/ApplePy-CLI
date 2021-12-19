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
    with open(filename, "a+") as log:
        log.write(str(datetime.now()) + " > " + str(data))


def _save_to_db(data):
    cursor = applepy.globals.con
    cursor.execute("INSERT INTO logs VALUES ('{0}', '{1}')".format(str(datetime.now()), str(data).replace("'", '"')))
    cursor.commit()


def echo(text, nl=False):
    click.echo(text, nl=nl)
    save_to_log(text)
    _save_to_db(text)
