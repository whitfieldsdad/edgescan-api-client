from typing import Optional
from edgescan.api.client import Client

import edgescan.serialization
import itertools
import click

from edgescan.cli.helpers import str_to_strs, str_to_ints, str_to_datetime


@click.group()
@click.pass_context
def hosts(_):
    """
    Query or count hosts.
    """
    pass


@hosts.command()
@click.option('--host-id', type=int, required=True)
@click.pass_context
def get_host(ctx: click.Context, host_id: int):
    """
    Lookup hosts by ID.
    """
    api = Client(**ctx.obj['config']['edgescan'])
    row = api.get_host(host_id=host_id)
    if row:
        txt = edgescan.serialization.to_json(row)
        click.echo(txt)


@hosts.command()
@click.option('--asset-ids')
@click.option('--asset-names')
@click.option('--asset-tags')
@click.option('--host-ids')
@click.option('--hostnames')
@click.option('--ip-addresses')
@click.option('--os-types')
@click.option('--os-versions')
@click.option('--alive/--dead', default=None)
@click.option('--vulnerability-ids')
@click.option('--vulnerability-names')
@click.option('--cve-ids')
@click.option('--min-asset-create-time')
@click.option('--max-asset-create-time')
@click.option('--min-asset-update-time')
@click.option('--max-asset-update-time')
@click.option('--min-next-assessment-time')
@click.option('--max-next-assessment-time')
@click.option('--min-last-assessment-time')
@click.option('--max-last-assessment-time')
@click.option('--min-last-host-scan-time')
@click.option('--max-last-host-scan-time')
@click.option('--min-host-last-seen-time')
@click.option('--max-host-last-seen-time')
@click.option('--min-vulnerability-create-time')
@click.option('--max-vulnerability-create-time')
@click.option('--min-vulnerability-update-time')
@click.option('--max-vulnerability-update-time')
@click.option('--min-vulnerability-open-time')
@click.option('--max-vulnerability-open-time')
@click.option('--min-vulnerability-close-time')
@click.option('--max-vulnerability-close-time')
@click.option('--limit', type=int)
@click.pass_context
def get_hosts(
        ctx: click.Context,
        asset_ids: Optional[str],
        asset_names: Optional[str],
        asset_tags: Optional[str],
        host_ids: Optional[str],
        hostnames: Optional[str],
        ip_addresses: Optional[str],
        os_types: Optional[str],
        os_versions: Optional[str],
        alive: Optional[bool],
        vulnerability_ids: Optional[str],
        vulnerability_names: Optional[str],
        cve_ids: Optional[str],
        min_asset_create_time: Optional[str],
        max_asset_create_time: Optional[str],
        min_asset_update_time: Optional[str],
        max_asset_update_time: Optional[str],
        min_next_assessment_time: Optional[str],
        max_next_assessment_time: Optional[str],
        min_last_assessment_time: Optional[str],
        max_last_assessment_time: Optional[str],
        min_last_host_scan_time: Optional[str],
        max_last_host_scan_time: Optional[str],
        min_host_last_seen_time: Optional[str],
        max_host_last_seen_time: Optional[str],
        min_vulnerability_create_time: Optional[str],
        max_vulnerability_create_time: Optional[str],
        min_vulnerability_update_time: Optional[str],
        max_vulnerability_update_time: Optional[str],
        min_vulnerability_open_time: Optional[str],
        max_vulnerability_open_time: Optional[str],
        min_vulnerability_close_time: Optional[str],
        max_vulnerability_close_time: Optional[str],
        limit: Optional[int]):
    """
    Search for matching hosts.
    """
    api = Client(**ctx.obj['config']['edgescan'])
    rows = api.iter_hosts(
        ids=str_to_ints(host_ids),
        hostnames=str_to_strs(hostnames),
        ip_addresses=str_to_strs(ip_addresses),
        os_types=str_to_strs(os_types),
        os_versions=str_to_strs(os_versions),
        alive=alive,
        asset_ids=str_to_ints(asset_ids),
        asset_names=str_to_strs(asset_names),
        asset_tags=str_to_strs(asset_tags),
        vulnerability_ids=str_to_ints(vulnerability_ids),
        vulnerability_names=str_to_strs(vulnerability_names),
        cve_ids=str_to_strs(cve_ids),
        min_asset_create_time=str_to_datetime(min_asset_create_time),
        max_asset_create_time=str_to_datetime(max_asset_create_time),
        min_asset_update_time=str_to_datetime(min_asset_update_time),
        max_asset_update_time=str_to_datetime(max_asset_update_time),
        min_next_assessment_time=str_to_datetime(min_next_assessment_time),
        max_next_assessment_time=str_to_datetime(max_next_assessment_time),
        min_last_assessment_time=str_to_datetime(min_last_assessment_time),
        max_last_assessment_time=str_to_datetime(max_last_assessment_time),
        min_last_host_scan_time=str_to_datetime(min_last_host_scan_time),
        max_last_host_scan_time=str_to_datetime(max_last_host_scan_time),
        min_host_last_seen_time=str_to_datetime(min_host_last_seen_time),
        max_host_last_seen_time=str_to_datetime(max_host_last_seen_time),
        min_vulnerability_create_time=str_to_datetime(min_vulnerability_create_time),
        max_vulnerability_create_time=str_to_datetime(max_vulnerability_create_time),
        min_vulnerability_update_time=str_to_datetime(min_vulnerability_update_time),
        max_vulnerability_update_time=str_to_datetime(max_vulnerability_update_time),
        min_vulnerability_open_time=str_to_datetime(min_vulnerability_open_time),
        max_vulnerability_open_time=str_to_datetime(max_vulnerability_open_time),
        min_vulnerability_close_time=str_to_datetime(min_vulnerability_close_time),
        max_vulnerability_close_time=str_to_datetime(max_vulnerability_close_time),
    )
    if limit is not None:
        rows = itertools.islice(rows, limit)

    for row in rows:
        txt = edgescan.serialization.to_json(row)
        click.echo(txt)


@hosts.command()
@click.option('--asset-ids')
@click.option('--asset-names')
@click.option('--asset-tags')
@click.option('--host-ids')
@click.option('--hostnames')
@click.option('--ip-addresses')
@click.option('--os-types')
@click.option('--os-versions')
@click.option('--alive/--dead', default=None)
@click.option('--vulnerability-ids')
@click.option('--vulnerability-names')
@click.option('--cve-ids')
@click.option('--min-asset-create-time')
@click.option('--max-asset-create-time')
@click.option('--min-asset-update-time')
@click.option('--max-asset-update-time')
@click.option('--min-next-assessment-time')
@click.option('--max-next-assessment-time')
@click.option('--min-last-assessment-time')
@click.option('--max-last-assessment-time')
@click.option('--min-last-host-scan-time')
@click.option('--max-last-host-scan-time')
@click.option('--min-host-last-seen-time')
@click.option('--max-host-last-seen-time')
@click.option('--min-vulnerability-create-time')
@click.option('--max-vulnerability-create-time')
@click.option('--min-vulnerability-update-time')
@click.option('--max-vulnerability-update-time')
@click.option('--min-vulnerability-open-time')
@click.option('--max-vulnerability-open-time')
@click.option('--min-vulnerability-close-time')
@click.option('--max-vulnerability-close-time')
@click.pass_context
def count_hosts(
        ctx: click.Context,
        asset_ids: Optional[str],
        asset_names: Optional[str],
        asset_tags: Optional[str],
        host_ids: Optional[str],
        hostnames: Optional[str],
        ip_addresses: Optional[str],
        os_types: Optional[str],
        os_versions: Optional[str],
        alive: Optional[bool],
        vulnerability_ids: Optional[str],
        vulnerability_names: Optional[str],
        cve_ids: Optional[str],
        min_asset_create_time: Optional[str],
        max_asset_create_time: Optional[str],
        min_asset_update_time: Optional[str],
        max_asset_update_time: Optional[str],
        min_next_assessment_time: Optional[str],
        max_next_assessment_time: Optional[str],
        min_last_assessment_time: Optional[str],
        max_last_assessment_time: Optional[str],
        min_last_host_scan_time: Optional[str],
        max_last_host_scan_time: Optional[str],
        min_host_last_seen_time: Optional[str],
        max_host_last_seen_time: Optional[str],
        min_vulnerability_create_time: Optional[str],
        max_vulnerability_create_time: Optional[str],
        min_vulnerability_update_time: Optional[str],
        max_vulnerability_update_time: Optional[str],
        min_vulnerability_open_time: Optional[str],
        max_vulnerability_open_time: Optional[str],
        min_vulnerability_close_time: Optional[str],
        max_vulnerability_close_time: Optional[str]):
    api = Client(**ctx.obj['config']['edgescan'])
    total = api.count_hosts(
        ids=str_to_ints(host_ids),
        hostnames=str_to_strs(hostnames),
        ip_addresses=str_to_strs(ip_addresses),
        os_types=str_to_strs(os_types),
        os_versions=str_to_strs(os_versions),
        alive=alive,
        asset_ids=str_to_ints(asset_ids),
        asset_names=str_to_strs(asset_names),
        asset_tags=str_to_strs(asset_tags),
        vulnerability_ids=str_to_ints(vulnerability_ids),
        vulnerability_names=str_to_strs(vulnerability_names),
        cve_ids=str_to_strs(cve_ids),
        min_asset_create_time=str_to_datetime(min_asset_create_time),
        max_asset_create_time=str_to_datetime(max_asset_create_time),
        min_asset_update_time=str_to_datetime(min_asset_update_time),
        max_asset_update_time=str_to_datetime(max_asset_update_time),
        min_next_assessment_time=str_to_datetime(min_next_assessment_time),
        max_next_assessment_time=str_to_datetime(max_next_assessment_time),
        min_last_assessment_time=str_to_datetime(min_last_assessment_time),
        max_last_assessment_time=str_to_datetime(max_last_assessment_time),
        min_last_host_scan_time=str_to_datetime(min_last_host_scan_time),
        max_last_host_scan_time=str_to_datetime(max_last_host_scan_time),
        min_host_last_seen_time=str_to_datetime(min_host_last_seen_time),
        max_host_last_seen_time=str_to_datetime(max_host_last_seen_time),
        min_vulnerability_create_time=str_to_datetime(min_vulnerability_create_time),
        max_vulnerability_create_time=str_to_datetime(max_vulnerability_create_time),
        min_vulnerability_update_time=str_to_datetime(min_vulnerability_update_time),
        max_vulnerability_update_time=str_to_datetime(max_vulnerability_update_time),
        min_vulnerability_open_time=str_to_datetime(min_vulnerability_open_time),
        max_vulnerability_open_time=str_to_datetime(max_vulnerability_open_time),
        min_vulnerability_close_time=str_to_datetime(min_vulnerability_close_time),
        max_vulnerability_close_time=str_to_datetime(max_vulnerability_close_time),
    )
    click.echo(total)
