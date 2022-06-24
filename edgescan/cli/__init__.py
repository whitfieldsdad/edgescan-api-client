from edgescan.cli.command_groups.assets import assets
from edgescan.cli.command_groups.hosts import hosts
from edgescan.cli.command_groups.licenses import licenses
from edgescan.cli.command_groups.vulnerabilities import vulnerabilities

import edgescan.cli.context
import click
import logging

from edgescan.constants import DEFAULT_HOST, DEFAULT_API_KEY

logging.basicConfig(level=logging.INFO)


@click.group()
@click.option('--edgescan-host', default=DEFAULT_HOST)
@click.option('--edgescan-api-key', default=DEFAULT_API_KEY)
@click.pass_context
def cli(ctx: click.Context, edgescan_host: str, edgescan_api_key: str):
    ctx.ensure_object(dict)
    ctx.obj |= edgescan.cli.context.get_context(
        edgescan_host=edgescan_host,
        edgescan_api_key=edgescan_api_key,
    )


COMMAND_GROUPS = [
    assets,
    hosts,
    licenses,
    vulnerabilities,
]
for command_group in COMMAND_GROUPS:
    cli.add_command(command_group)
