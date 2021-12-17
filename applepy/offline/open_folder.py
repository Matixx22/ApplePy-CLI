import io
import pathlib
import applepy.offline.open_file as of
import click

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-f', '--filter', help='Applies filter to displayed packets', type=str)
@click.argument('folder', type=str)
def open_pcap_folder(folder, filter):
    matches = pathlib.Path(folder).glob("**/*.pcap")
    matches_list = sorted(matches)
    for file in matches_list:
        of.open_pcap(None, io.open(file), filter)
