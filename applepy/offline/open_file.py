import click
from click.exceptions import ClickException
from scapy.all import sniff
from scapy.error import Scapy_Exception


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
