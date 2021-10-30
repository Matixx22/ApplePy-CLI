import click
from scapy.all import sniff


@click.command()
@click.option('-i', '--index', help="Packet's index counting from 0. If not specified then displaying all the packets", type=int)
@click.option('-f', '--filter', help='Applies filter to displayed packets', type=str)
@click.argument('file', type=click.File('rb'))
def open(index, file, filter):
    """Displays the given file"""

    # TODO: Check file extensions, index, filter and hundreds of other things

    packets = sniff(offline=file, filter=filter)

    if index is None:
        click.echo(packets.nsummary())
    else:
        if index < 0 or index >= len(packets):
            click.echo(
                f'There is no packet with the given index. Index range 0-{len(packets)-1} ')
            exit(0)

        click.echo(f'Packet #{str(index)}')
        click.echo(packets[index].show())
