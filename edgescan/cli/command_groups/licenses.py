from typing import Optional
from edgescan.api.client import Client

import itertools
import click

import edgescan.serialization
from edgescan.cli.helpers import str_to_strs, str_to_ints


@click.group()
@click.pass_context
def licenses(_):
    """
    Query or count licenses.
    """
    pass


@licenses.command()
@click.option('--license-id', type=int, required=True)
@click.pass_context
def get_license(ctx: click.Context, license_id: int):
    api = Client(**ctx.obj['config']['edgescan'])
    row = api.get_license(license_id)
    if row:
        txt = edgescan.serialization.to_json(row)
        click.echo(txt)


@licenses.command()
@click.option('--license-ids')
@click.option('--license-names')
@click.option('--expired/--not-expired', default=None)
@click.option('--limit', type=int)
@click.pass_context
def get_licenses(
        ctx: click.Context,
        license_ids: Optional[str],
        license_names: Optional[str],
        expired: Optional[bool],
        limit: Optional[int]):
    api = Client(**ctx.obj['config']['edgescan'])
    rows = api.iter_licenses(
        ids=str_to_ints(license_ids),
        names=str_to_strs(license_names),
        expired=expired,
    )
    if limit:
        rows = itertools.islice(rows, limit)

    for row in rows:
        txt = edgescan.serialization.to_json(row)
        click.echo(txt)


@licenses.command()
@click.option('--license-ids')
@click.option('--license-names')
@click.option('--expired/--not-expired', default=None)
@click.pass_context
def count_licenses(
        ctx: click.Context,
        license_ids: Optional[str],
        license_names: Optional[str],
        expired: Optional[bool]):
    api = Client(**ctx.obj['config']['edgescan'])
    total = api.count_licenses(
        ids=str_to_ints(license_ids),
        names=str_to_strs(license_names),
        expired=expired,
    )
    click.echo(total)
