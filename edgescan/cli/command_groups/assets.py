from typing import Optional
from edgescan.api.client import Client
from edgescan.cli.helpers import str_to_strs, str_to_ints, str_to_datetime

import click
import itertools
import edgescan.serialization


@click.group()
def assets():
    """
    Query or count assets.
    """
    pass


@assets.command()
@click.option('--asset-id', type=int, required=True)
def get_asset(asset_id: int):
    """
    Lookup assets.
    """
    api = Client()
    row = api.get_asset(asset_id=asset_id)
    if row:
        txt = edgescan.serialization.to_json(row)
        click.echo(txt)


@assets.command()
@click.option('--asset-ids')
@click.option('--names')
@click.option('--tags')
@click.option('--min-create-time')
@click.option('--max-create-time')
@click.option('--min-update-time')
@click.option('--max-update-time')
@click.option('--limit', type=int)
def get_assets(
        asset_ids: Optional[str],
        names: Optional[str],
        tags: Optional[str],
        min_create_time: Optional[str],
        max_create_time: Optional[str],
        min_update_time: Optional[str],
        max_update_time: Optional[str],
        limit: Optional[int] = None):
    """
    Search for assets.
    """
    api = Client()
    rows = api.iter_assets(
        ids=str_to_ints(asset_ids),
        names=str_to_strs(names),
        tags=str_to_strs(tags),
        min_create_time=str_to_datetime(min_create_time),
        max_create_time=str_to_datetime(max_create_time),
        min_update_time=str_to_datetime(min_update_time),
        max_update_time=str_to_datetime(max_update_time),
    )
    for row in itertools.islice(rows, limit):
        txt = edgescan.serialization.to_json(row)
        click.echo(txt)


@assets.command()
@click.option('--asset-ids')
@click.option('--names')
@click.option('--tags')
@click.option('--min-create-time')
@click.option('--max-create-time')
@click.option('--min-update-time')
@click.option('--max-update-time')
def count_assets(
        asset_ids: Optional[str],
        names: Optional[str],
        tags: Optional[str],
        min_create_time: Optional[str],
        max_create_time: Optional[str],
        min_update_time: Optional[str],
        max_update_time: Optional[str]):
    """
    Count assets.
    """
    api = Client()
    total = api.count_assets(
        ids=str_to_ints(asset_ids),
        names=str_to_strs(names),
        tags=str_to_strs(tags),
        min_create_time=str_to_datetime(min_create_time),
        max_create_time=str_to_datetime(max_create_time),
        min_update_time=str_to_datetime(min_update_time),
        max_update_time=str_to_datetime(max_update_time),
    )
    click.echo(total)
