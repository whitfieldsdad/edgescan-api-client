import collections
import gzip
import hashlib
import json
import os.path
import shutil
import tempfile
from typing import Iterator, Any, Optional, Dict
from edgescan.constants import DEFAULT_API_KEY, DEFAULT_HOST, HOSTS, ASSETS, VULNERABILITIES
from edgescan.data.types.host import Host
from edgescan.data.types.license import License
from edgescan.data.types.vulnerability import Vulnerability
from edgescan.data.parser import CREATE_TIME, UPDATE_TIME

import edgescan.logging
import edgescan.logging
import edgescan.time
import edgescan.patterns
import edgescan.data.parser as parser
import edgescan.api.session
import urllib.parse

from edgescan.type_hints import TIME, STRS, INTS

import logging

logger = logging.getLogger(__name__)


class Client:
    def __init__(self, host: str = DEFAULT_HOST, api_key: str = DEFAULT_API_KEY):
        self.host = host
        self.url = 'https://' + host
        self.session = edgescan.api.session.get_session(api_key=api_key)

    @property
    def hosts_url(self) -> str:
        return urllib.parse.urljoin(self.url, 'api/v1/hosts.json')

    @property
    def assets_url(self) -> str:
        return urllib.parse.urljoin(self.url, 'api/v1/assets.json')

    @property
    def vulnerabilities_url(self) -> str:
        return urllib.parse.urljoin(self.url, 'api/v1/vulnerabilities.json')

    @property
    def download_urls(self) -> Dict[str, str]:
        return {
            HOSTS: self.hosts_url,
            ASSETS: self.assets_url,
            VULNERABILITIES: self.vulnerabilities_url,
        }

    def get_download_url(self, resource_type: str) -> str:
        return self.download_urls[resource_type]

    def iter_objects(
            self,
            resource_type: str,
            ids: Optional[INTS] = None,
            names: Optional[STRS] = None,
            min_create_time: Optional[TIME] = None,
            max_create_time: Optional[TIME] = None,
            min_update_time: Optional[TIME] = None,
            max_update_time: Optional[TIME] = None) -> Iterator[dict]:

        ids = frozenset(ids) if ids else None
        names = frozenset(names) if names else None

        rows = self._iter_objects(resource_type=resource_type)
        for row in rows:

            #: Filter objects by ID.
            if ids and row['id'] not in ids:
                continue

            #: Fit objects to timeframe.
            for attr, min_time, max_time in [
                [CREATE_TIME, min_create_time, max_create_time],
                [UPDATE_TIME, min_update_time, max_update_time],
            ]:
                if min_time or max_time:
                    t = parser.get(row, attr)
                    if t is None or not edgescan.time.in_range(t, min_time, max_time):
                        continue

            #: Filter objects by name.
            if names and not edgescan.patterns.matches(row['name'], names):
                continue

            yield row

    def _iter_objects(self, resource_type: str) -> Iterator[dict]:
        url = self.download_urls[resource_type]
        response = self.session.head(url)

        #: Identify the latest version of the data.
        version = hashlib.md5(response.headers['ETag'].encode('utf-8')).hexdigest()

        #: Cache the latest version of the data locally in a JSONL file in the system's temporary directory.
        tmp_dir = os.path.join(tempfile.gettempdir(), 'edgescan', resource_type)
        path = os.path.join(tmp_dir, version + '.jsonl.gz')

        #: Remove empty files.
        if os.path.exists(path) and os.path.getsize(path) == 0:
            os.unlink(path)

        #: Download the file if it hasn't already been downloaded yet.
        if not os.path.exists(path):
            if os.path.exists(tmp_dir):
                shutil.rmtree(tmp_dir)

            os.makedirs(tmp_dir, exist_ok=True)
            response = self.session.get(url)
            response.raise_for_status()

            logger.info("Writing %s to %s", resource_type, path)
            with gzip.open(path, 'w') as fp:
                for row in response.json()[resource_type]:
                    if row:
                        txt = json.dumps(row) + '\n'
                        fp.write(txt.encode('utf-8'))

        #: Always read from the filesystem to provide a closed loop.
        logger.info("Reading %s from %s", resource_type, path)
        with gzip.open(path, 'rb') as fp:
            for line in fp:
                line = line.strip()
                if line:
                    row = json.loads(line)
                    yield row

    def count_objects(
            self,
            resource_type: str,
            min_create_time: Optional[TIME] = None,
            max_create_time: Optional[TIME] = None,
            min_update_time: Optional[TIME] = None,
            max_update_time: Optional[TIME] = None) -> int:

        if min_create_time or max_create_time or min_update_time or max_update_time:
            rows = self.iter_objects(
                resource_type=resource_type,
                min_create_time=min_create_time,
                max_create_time=max_create_time,
                min_update_time=min_update_time,
                max_update_time=max_update_time,
            )
            total = _len(rows)
        else:
            url = self.download_urls[resource_type]
            response = self.session.get(url)
            response.raise_for_status()

            reply = response.json()
            total = reply['total']
        return total

    def get_asset(self, asset_id: int) -> Optional[dict]:
        return next(self.iter_assets(ids=[asset_id]), None)
    
    def iter_assets(
            self,
            ids: Optional[INTS] = None,
            names: Optional[STRS] = None,
            tags: Optional[STRS] = None,
            min_create_time: Optional[TIME] = None,
            max_create_time: Optional[TIME] = None,
            min_update_time: Optional[TIME] = None,
            max_update_time: Optional[TIME] = None) -> Iterator[dict]:

        kwargs = locals()
        del kwargs['self']

        if any(kwargs.values()):
            hint = edgescan.logging.get_hint(**kwargs)
            logger.info("Listing assets (%s)", hint)
        else:
            logger.info("Listing assets")

        for asset in self.iter_objects(
            resource_type=ASSETS,
            ids=ids,
            names=names,
            min_create_time=min_create_time,
            max_create_time=max_create_time,
            min_update_time=min_update_time,
            max_update_time=max_update_time,
        ):
            #: Filter assets by tag.
            if tags and not edgescan.patterns.matches(asset['tags'], tags):
                continue

            yield asset

    def count_assets(
            self,
            ids: Optional[INTS] = None,
            names: Optional[STRS] = None,
            tags: Optional[STRS] = None,
            min_create_time: Optional[TIME] = None,
            max_create_time: Optional[TIME] = None,
            min_update_time: Optional[TIME] = None,
            max_update_time: Optional[TIME] = None) -> int:

        kwargs = locals()
        del kwargs['self']

        if any(kwargs.values()):
            logger.info("Counting assets (%s)", edgescan.logging.get_hint(**kwargs))
        else:
            logger.info("Counting assets")

        assets = self.iter_assets(
            ids=ids,
            names=names,
            tags=tags,
            min_create_time=min_create_time,
            max_create_time=max_create_time,
            min_update_time=min_update_time,
            max_update_time=max_update_time,
        )
        return _len(assets)

    def get_host(self, host_id: int) -> Optional[Host]:
        return next(self.iter_hosts(ids=[host_id]), None)

    def iter_hosts(
            self,
            ids: Optional[INTS] = None,
            locations: Optional[STRS] = None,
            alive: Optional[bool] = None,
            asset_ids: Optional[INTS] = None,
            min_create_time: Optional[TIME] = None,
            max_create_time: Optional[TIME] = None,
            min_update_time: Optional[TIME] = None,
            max_update_time: Optional[TIME] = None) -> Iterator[dict]:

        kwargs = locals()
        del kwargs['self']

        if any(kwargs.values()):
            hint = edgescan.logging.get_hint(**kwargs)
            logger.info("Listing hosts (%s)", hint)
        else:
            logger.info("Listing hosts")

        for host in self.iter_objects(
            resource_type=HOSTS,
            ids=ids,
            min_create_time=min_create_time,
            max_create_time=max_create_time,
            min_update_time=min_update_time,
            max_update_time=max_update_time,
        ):
            if asset_ids and host['asset_id'] not in asset_ids:
                continue

            if locations and not edgescan.patterns.matches(host['location'], locations):
                pass

            if alive is not None:
                status = host['status']
                if alive is True and status != 'alive':
                    continue

                if alive is False and status == 'alive':
                    continue

            yield host

    def count_hosts(
            self,
            ids: Optional[INTS] = None,
            locations: Optional[STRS] = None,
            alive: Optional[bool] = None,
            asset_ids: Optional[INTS] = None,
            min_create_time: Optional[TIME] = None,
            max_create_time: Optional[TIME] = None,
            min_update_time: Optional[TIME] = None,
            max_update_time: Optional[TIME] = None) -> int:

        kwargs = locals()
        del kwargs['self']

        if any(kwargs.values()):
            logger.info("Counting hosts (%s)", edgescan.logging.get_hint(**kwargs))
        else:
            logger.info("Counting hosts")

        hosts = self.iter_hosts(
            ids=ids,
            locations=locations,
            asset_ids=asset_ids,
            alive=alive,
            min_create_time=min_create_time,
            max_create_time=max_create_time,
            min_update_time=min_update_time,
            max_update_time=max_update_time,
        )
        return _len(hosts)

    def get_vulnerability(self, vulnerability_id: int) -> Optional[Vulnerability]:
        return next(self.iter_vulnerabilities(ids=[vulnerability_id]), None)

    def iter_vulnerabilities(
            self,
            ids: Optional[INTS] = None,
            cve_ids: Optional[STRS] = None,
            asset_ids: Optional[INTS] = None,
            host_ids: Optional[INTS] = None,
            host_is_alive: Optional[bool] = None,
            locations: Optional[STRS] = None,
            include_application_layer_vulnerabilities: Optional[bool] = True,
            include_network_layer_vulnerabilities: Optional[bool] = True,
            min_create_time: Optional[TIME] = None,
            max_create_time: Optional[TIME] = None,
            min_update_time: Optional[TIME] = None,
            max_update_time: Optional[TIME] = None) -> Iterator[dict]:

        kwargs = locals()
        del kwargs['self']

        if any(kwargs.values()):
            hint = edgescan.logging.get_hint(**kwargs)
            logger.info("Listing vulnerabilities (%s)", hint)
        else:
            logger.info("Listing vulnerabilities")

        #: Hosts are linked to vulnerabilities by location.
        if locations or host_ids or host_is_alive:
            locations = set(locations) if locations else set()
            hosts = tuple(self.iter_hosts(ids=host_ids, locations=locations, alive=host_is_alive))
            for host in hosts:
                locations.add(host['location'])
                locations.update(set(host['hostnames']))

            #: No matching locations means no matching hosts
            if not locations:
                return

        for vulnerability in self.iter_objects(
            resource_type=VULNERABILITIES,
            ids=ids,
            min_create_time=min_create_time,
            max_create_time=max_create_time,
            min_update_time=min_update_time,
            max_update_time=max_update_time,
        ):
            #: Filter vulnerabilities by asset ID.
            if asset_ids and vulnerability['asset_id'] not in asset_ids:
                continue

            #: Filter vulnerabilities by location.
            if locations and vulnerability['location'] not in locations:
                continue

            #: Filter vulnerabilities by CVE ID.
            if cve_ids and set(cve_ids).isdisjoint(set(vulnerability['cves'])):
                continue

            #: Filter vulnerabilities by layer.
            if include_application_layer_vulnerabilities or include_network_layer_vulnerabilities:
                layer = vulnerability['layer']
                if layer == 'app' and include_application_layer_vulnerabilities is False:
                    continue
                elif layer == 'network' and include_network_layer_vulnerabilities is False:
                    continue

            yield vulnerability

    def count_vulnerabilities(
            self,
            ids: Optional[INTS] = None,
            cve_ids: Optional[STRS] = None,
            asset_ids: Optional[INTS] = None,
            host_ids: Optional[INTS] = None,
            host_is_alive: Optional[bool] = None,
            locations: Optional[STRS] = None,
            include_application_layer_vulnerabilities: Optional[bool] = True,
            include_network_layer_vulnerabilities: Optional[bool] = True,
            min_create_time: Optional[TIME] = None,
            max_create_time: Optional[TIME] = None,
            min_update_time: Optional[TIME] = None,
            max_update_time: Optional[TIME] = None) -> int:

        kwargs = locals()
        del kwargs['self']

        if any(kwargs.values()):
            logger.info("Counting vulnerabilities (%s)", edgescan.logging.get_hint(**kwargs))
        else:
            logger.info("Counting vulnerabilities")

        vulnerabilities = self.iter_vulnerabilities(
            ids=ids,
            cve_ids=cve_ids,
            asset_ids=asset_ids,
            host_ids=host_ids,
            locations=locations,
            include_application_layer_vulnerabilities=include_application_layer_vulnerabilities,
            include_network_layer_vulnerabilities=include_network_layer_vulnerabilities,
            host_is_alive=host_is_alive,
            min_create_time=min_create_time,
            max_create_time=max_create_time,
            min_update_time=min_update_time,
            max_update_time=max_update_time,
        )
        return _len(vulnerabilities)

    def get_license(self, license_id: int) -> Optional[License]:
        return next(self.iter_licenses(ids=[license_id]), None)

    def iter_licenses(
            self,
            ids: Optional[INTS] = None,
            names: Optional[STRS] = None,
            expired: Optional[bool] = None) -> Iterator[dict]:

        kwargs = locals()
        del kwargs['self']

        if any(kwargs.values()):
            hint = edgescan.logging.get_hint(**kwargs)
            logger.info("Listing licenses (%s)", hint)
        else:
            logger.info("Listing licenses")

        for row in self._iter_licenses():
            if ids and row['id'] not in ids:
                continue

            if names and not edgescan.patterns.matches(row['name'], names):
                continue

            if expired is not None and row['expired'] != expired:
                continue

            yield row

    def _iter_licenses(self) -> Iterator[dict]:
        seen = set()
        for asset in self.iter_assets():
            active_license = asset['active_licence']
            if active_license['id'] not in seen:
                seen.add(active_license['id'])
                yield active_license

    def count_licenses(
            self,
            ids: Optional[INTS] = None,
            names: Optional[STRS] = None,
            expired: Optional[bool] = None) -> int:

        kwargs = locals()
        del kwargs['self']

        if any(kwargs.values()):
            logger.info("Counting licenses (%s)", edgescan.logging.get_hint(**kwargs))
        else:
            logger.info("Counting licenses")

        licenses = self.iter_licenses(
            ids=ids,
            names=names,
            expired=expired,
        )
        return _len(licenses)

def _len(it: Any) -> int:
    try:
        return len(it)
    except TypeError:
        return sum(1 for _ in it)
