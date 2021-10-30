import click

from .offline import open_file


@click.group()
def cli():
    pass


# @cli.command()
# def check_if_kacper_nie_zda():
#     """This command checks if Kacper nie zda"""
#     click.echo('Kacper nie zda')


# @cli.command()
# def dropdb():
#     click.echo('Dropped the database')


# @cli.command()
# @click.option('--count', default=1, help='number of greetings')
# @click.argument('name')
# def hello(count, name):
#     for x in range(count):
#         click.echo(f"Hello {name}!")

cli.add_command(open_file.open)
