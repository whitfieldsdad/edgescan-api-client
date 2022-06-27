from typing import Optional
from edgescan.api.client import Client

import edgescan.serialization
import itertools
import click

from edgescan.cli.helpers import str_to_strs, str_to_ints, str_to_datetime


@click.group()
def hosts():
    """
    Query or count hosts.
    """
    pass


@hosts.command()
@click.option('--host-id', type=int, required=True)
def get_host(host_id: int):
    """
    Lookup hosts by ID.
    """
    api = Client()
    row = api.get_host(host_id=host_id)
    if row:
        txt = edgescan.serialization.to_json(row)
        click.echo(txt)


@hosts.command()
@click.option('--asset-ids')
@click.option('--host-ids')
@click.option('--locations')
@click.option('--alive/--dead', default=None, show_default=True)
@click.option('--min-create-time')
@click.option('--max-create-time')
@click.option('--min-update-time')
@click.option('--max-update-time')
@click.option('--limit', type=int)
def get_hosts(
        asset_ids: Optional[str],
        host_ids: Optional[str],
        locations: Optional[str],
        alive: Optional[bool],
        min_create_time: Optional[str],
        max_create_time: Optional[str],
        min_update_time: Optional[str],
        max_update_time: Optional[str],
        limit: Optional[int]):
    """
    Search for hosts.
    """
    api = Client()
    rows = api.iter_hosts(
        ids=str_to_ints(host_ids),
        locations=str_to_strs(locations),
        alive=alive,
        asset_ids=str_to_ints(asset_ids),
        min_create_time=str_to_datetime(min_create_time),
        max_create_time=str_to_datetime(max_create_time),
        min_update_time=str_to_datetime(min_update_time),
        max_update_time=str_to_datetime(max_update_time),
    )
    for row in itertools.islice(rows, limit):
        txt = edgescan.serialization.to_json(row)
        click.echo(txt)


@hosts.command()
@click.option('--asset-ids')
@click.option('--host-ids')
@click.option('--locations')
@click.option('--alive/--dead', default=None, show_default=True)
@click.option('--min-create-time')
@click.option('--max-create-time')
@click.option('--min-update-time')
@click.option('--max-update-time')
def count_hosts(
        asset_ids: Optional[str],
        host_ids: Optional[str],
        locations: Optional[str],
        alive: Optional[bool],
        min_create_time: Optional[str],
        max_create_time: Optional[str],
        min_update_time: Optional[str],
        max_update_time: Optional[str]):
    """
    Count hosts.
    """
    api = Client()
    total = api.count_hosts(
        ids=str_to_ints(host_ids),
        locations=str_to_strs(locations),
        alive=alive,
        asset_ids=str_to_ints(asset_ids),
        min_create_time=str_to_datetime(min_create_time),
        max_create_time=str_to_datetime(max_create_time),
        min_update_time=str_to_datetime(min_update_time),
        max_update_time=str_to_datetime(max_update_time),
    )
    click.echo(total)
