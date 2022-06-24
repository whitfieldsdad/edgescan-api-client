from typing import Optional
from edgescan.constants import ASSETS, VULNERABILITIES, HOSTS
from edgescan.data.types.assessment import Assessment
from edgescan.data.types.asset import Asset
from edgescan.data.types.host import Host
from edgescan.data.types.license import License
from edgescan.data.types.location_specifier import LocationSpecifier
from edgescan.data.types.vulnerability import Vulnerability

import edgescan.types
import edgescan.time


def parse_object(data: dict, collection_type: str):
    parser = _PARSERS_BY_COLLECTION_TYPE[collection_type]
    return parser(data)


def parse_asset(data: dict) -> Asset:
    data |= _parse_timestamps(data)
    data |= {
        'active_license': parse_license(data.pop('active_licence')),
        'last_host_scan': edgescan.time.to_datetime(data['last_host_scan']),
        'location_specifiers': [loc for loc in data['location_specifiers']],
    }
    assessment = data['current_assessment']
    if assessment:
        data['current_assessment'] = parse_assessment(assessment)
    return edgescan.types.dict_to_dataclass(data, Asset)


def parse_vulnerability(data: dict) -> Vulnerability:
    data |= _parse_timestamps(data)
    return edgescan.types.dict_to_dataclass(data, Vulnerability)


def parse_assessment(data: dict) -> Assessment:
    data |= _parse_timestamps(data)
    return edgescan.types.dict_to_dataclass(data, Assessment)


def parse_license(data: dict) -> License:
    data |= {
        'license_type_id': data.pop('licence_type_id'),
        'license_type_name': data.pop('licence_type_name'),
    }
    data |= _parse_timestamps(data)
    return edgescan.types.dict_to_dataclass(data, License)


def parse_host(data: dict) -> Host:
    data = _parse_timestamps(data)
    return edgescan.types.dict_to_dataclass(data, Host)


def parse_location_specifier(data: dict) -> LocationSpecifier:
    return edgescan.types.dict_to_dataclass(data, LocationSpecifier)


def _parse_timestamps(data: Optional[dict]) -> Optional[dict]:
    if data:
        for k, v in data.items():
            if k.startswith('date_') or k.endswith(('_at', '_date', '_time')):
                data[k] = edgescan.time.to_datetime(v)
    return data


_PARSERS_BY_COLLECTION_TYPE = {
    ASSETS: parse_asset,
    VULNERABILITIES: parse_vulnerability,
    HOSTS: parse_host,
}
