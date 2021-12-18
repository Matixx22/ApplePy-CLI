import sys

import click

from .offline import open_file
import applepy.globals
from applepy.save_to_log import save_to_log

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    applepy.globals.init()

    # Saving current command to log
    command = ""
    for command_part in sys.argv:
        command += command_part + " "
    save_to_log(command + "\n")
    pass


cli.add_command(open_file.open_pcap)
cli.add_command(open_file.open_text)
cli.add_command(open_file.open_evtx)
