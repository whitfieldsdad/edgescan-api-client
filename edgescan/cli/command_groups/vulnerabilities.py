from typing import Optional
from edgescan.api.client import Client

import itertools
import edgescan.serialization
import click

from edgescan.cli.helpers import str_to_strs, str_to_ints, str_to_datetime


@click.group()
def vulnerabilities():
    """
    Query or count vulnerabilities.
    """
    pass


@vulnerabilities.command()
@click.option('--vulnerability-id', type=int, required=True)
def get_vulnerability(vulnerability_id: int):
    """
    Lookup vulnerabilities.
    """
    api = Client()
    row = api.get_vulnerability(vulnerability_id)
    if row:
        txt = edgescan.serialization.to_json(row)
        click.echo(txt)


@vulnerabilities.command()
@click.option('--vulnerability-ids')
@click.option('--cve-ids')
@click.option('--asset-ids')
@click.option('--host-ids')
@click.option('--locations')
@click.option('--alive/--dead', 'host_is_alive', default=None)
@click.option('--include-application-layer-vulnerabilities/--exclude-application-layer-vulnerabilities', default=True)
@click.option('--include-network-layer-vulnerabilities/--exclude-network-layer-vulnerabilities', default=True)
@click.option('--min-create-time')
@click.option('--max-create-time')
@click.option('--min-update-time')
@click.option('--max-update-time')
@click.option('--limit', type=int)
def get_vulnerabilities(
        vulnerability_ids: Optional[str],
        cve_ids: Optional[str],
        asset_ids: Optional[str],
        host_ids: Optional[str],
        locations: Optional[str],
        host_is_alive: Optional[bool],
        include_application_layer_vulnerabilities: Optional[bool],
        include_network_layer_vulnerabilities: Optional[bool],
        min_create_time: Optional[str],
        max_create_time: Optional[str],
        min_update_time: Optional[str],
        max_update_time: Optional[str],
        limit: int):
    """
    List vulnerabilities.
    """
    api = Client()
    rows = api.iter_vulnerabilities(
        ids=str_to_ints(vulnerability_ids),
        cve_ids=str_to_strs(cve_ids),
        host_ids=str_to_ints(host_ids),
        asset_ids=str_to_ints(asset_ids),
        locations=str_to_strs(locations),
        host_is_alive=host_is_alive,
        include_application_layer_vulnerabilities=include_application_layer_vulnerabilities,
        include_network_layer_vulnerabilities=include_network_layer_vulnerabilities,
        min_create_time=str_to_datetime(min_create_time),
        max_create_time=str_to_datetime(max_create_time),
        min_update_time=str_to_datetime(min_update_time),
        max_update_time=str_to_datetime(max_update_time),
    )
    for row in itertools.islice(rows, limit):
        txt = edgescan.serialization.to_json(row)
        click.echo(txt)


@vulnerabilities.command()
@click.option('--vulnerability-ids')
@click.option('--cve-ids')
@click.option('--asset-ids')
@click.option('--host-ids')
@click.option('--locations')
@click.option('--alive/--dead', 'host_is_alive', default=None)
@click.option('--include-application-layer-vulnerabilities/--exclude-application-layer-vulnerabilities', default=True)
@click.option('--include-network-layer-vulnerabilities/--exclude-network-layer-vulnerabilities', default=True)
@click.option('--min-create-time')
@click.option('--max-create-time')
@click.option('--min-update-time')
@click.option('--max-update-time')
def count_vulnerabilities(
        vulnerability_ids: Optional[str],
        cve_ids: Optional[str],
        asset_ids: Optional[str],
        host_ids: Optional[str],
        locations: Optional[str],
        host_is_alive: Optional[bool],
        include_application_layer_vulnerabilities: Optional[bool],
        include_network_layer_vulnerabilities: Optional[bool],
        min_create_time: Optional[str],
        max_create_time: Optional[str],
        min_update_time: Optional[str],
        max_update_time: Optional[str]):
    """
    Count vulnerabilities.
    """
    api = Client()
    total = api.count_vulnerabilities(
        ids=str_to_ints(vulnerability_ids),
        cve_ids=str_to_strs(cve_ids),
        host_ids=str_to_ints(host_ids),
        host_is_alive=host_is_alive,
        asset_ids=str_to_ints(asset_ids),
        locations=str_to_strs(locations),
        include_application_layer_vulnerabilities=include_application_layer_vulnerabilities,
        include_network_layer_vulnerabilities=include_network_layer_vulnerabilities,
        min_create_time=str_to_datetime(min_create_time),
        max_create_time=str_to_datetime(max_create_time),
        min_update_time=str_to_datetime(min_update_time),
        max_update_time=str_to_datetime(max_update_time),
    )
    click.echo(total)
