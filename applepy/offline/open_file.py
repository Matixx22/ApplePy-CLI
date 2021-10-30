import click
import pyshark
from scapy.all import *


@click.command()
@click.option('-i', '--index', required=True, help="Packet's index counting from 0", type=int)
@click.argument('file', type=click.File('rb'))
def open(index, file):
    """Loads the given file"""

    # TODO: Check file extensions and hundreds of other things

    packtes = pyshark.FileCapture(file)

    click.echo(packtes[index])
