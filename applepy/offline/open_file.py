import click
import re
import Evtx.Evtx as evtx
from click.exceptions import ClickException
from scapy.all import sniff
from scapy.error import Scapy_Exception
from collections import OrderedDict


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-i', '--index', help="""Packet's index counting from 0.
                                       If not specified then displaying all the packets.
                                       If used with filter flag, takes an index of filtered packets""", type=int)
@click.option('-f', '--filter', help='Applies filter to displayed packets', type=str)
@click.argument('file', type=click.File('rb'))
def open_pcap(index, file, filter):
    """
    Displays a packet capture file

    FILE is a packet capture file to be displayed
    """

    try:
        # Loads packet capture file
        packets = sniff(offline=file, filter=filter)

        if index is None:
            click.echo(packets.nsummary())
        else:
            if index < 0 or index >= len(packets):
                raise ClickException(
                    f'There is no packet with the given index. Index range 0-{len(packets)-1}')

            click.echo(f'Packet #{str(index)}')
            click.echo(packets[index].show())

    except Scapy_Exception as e:
        click.echo(e)
        exit(1)


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-g', '--grep', help='Applies grep filter to displayed content', type=str)
@click.option('-r', '--regex', help='Applies regular expresion filter to displayed content', type=str)
@click.argument('file', type=click.File('r'))
def open_txt(file, grep, regex):
    """
    Displays a txt file

    FILE is a txt file to be displayed
    """

    # TODO: Nie wiem jak rozroznic grepa od re, nie dziala \

    for line in file:
        if grep is None and regex is None:
            click.echo(line, nl=False)
        elif grep is not None and regex is None:
            if re.findall(grep, line):
                click.echo(line, nl=False)
        elif grep is None and regex is not None:
            user_regex = re.compile(regex)
            # print(type(user_regex))
            if re.findall(user_regex, line):
                click.echo(line, nl=False)
        else:
            click.echo('Apply only one filter')

@click.command(context_settings=CONTEXT_SETTINGS)
@click.argument('file', type=click.Path(exists=True))
def open_evtx(file):
    """
    Displays an evtx file

    FILE is an evtx file to be displayed
    """

    with evtx.Evtx(file) as open_log:
        header = open_log.get_file_header()
        properties = OrderedDict(
            [
                ("major_version", "File version (major)"),
                ("minor_version", "File version (minor)"),
                ("is_dirty", "File is dirty"),
                ("is_full", "File is full"),
                ("next_record_number", "Next record number"),
            ]
        )

        for key, value in properties.items():
            click.echo(f"{value}: {getattr(header, key)()}")

        for record in open_log.records():
            click.echo(record.xml())