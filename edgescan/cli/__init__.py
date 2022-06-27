from edgescan.cli.command_groups.assets import assets
from edgescan.cli.command_groups.hosts import hosts
from edgescan.cli.command_groups.licenses import licenses
from edgescan.cli.command_groups.vulnerabilities import vulnerabilities

import click
import logging

logging.basicConfig(level=logging.INFO)


@click.group()
def cli():
    pass


COMMAND_GROUPS = [
    assets,
    hosts,
    licenses,
    vulnerabilities,
]
for command_group in COMMAND_GROUPS:
    cli.add_command(command_group)
