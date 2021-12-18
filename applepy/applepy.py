import click

from .offline import open_file


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    pass


cli.add_command(open_file.open_pcap)
cli.add_command(open_file.open_text)
