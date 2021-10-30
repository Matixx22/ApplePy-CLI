import click


@click.group()
def cli():
    pass

@cli.command()
def check_if_kacper_nie_zda():
    click.echo('Kacper nie zda')

@cli.command()
def dropdb():
    click.echo('Dropped the database')

if __name__ == '__main__':
    cli()
