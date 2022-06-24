from dataclasses import dataclass
from typing import Optional, List, Union

import edgescan.patterns
import edgescan.platforms
import edgescan.time
import ipaddress
import datetime


@dataclass(frozen=True)
class Host:
    id: int
    asset_id: int
    location: str
    hostnames: List[str]
    label: Optional[str]
    status: str
    updated_at: datetime.datetime
    os_name: str
    apis_detected: bool

    @property
    def ip_address(self) -> Optional[str]:
        try:
            return str(ipaddress.ip_address(self.location))
        except ipaddress.AddressValueError:
            return

    @property
    def os_type(self) -> str:
        return edgescan.platforms.parse_os_type(self.os_name)

    @property
    def os_version(self) -> str:
        return self.os_name

    @property
    def locations(self) -> List[str]:
        return [self.location] + self.hostnames

    @property
    def update_time(self) -> datetime.datetime:
        return self.updated_at

    @property
    def last_seen_time(self) -> datetime.datetime:
        return self.updated_at

    def is_alive(self) -> bool:
        return self.status == 'alive'

    def matches(
            self,
            ids: Optional[List[int]] = None,
            locations: Optional[List[str]] = None,
            os_types: Optional[List[str]] = None,
            os_versions: Optional[List[str]] = None,
            alive: Optional[bool] = None,
            min_last_seen_time: Optional[Union[str, int, float, datetime.datetime, datetime.date]] = None,
            max_last_seen_time: Optional[Union[str, int, float, datetime.datetime, datetime.date]] = None,
            asset_ids: Optional[List[int]] = None) -> bool:

        #: Filter hosts by ID.
        if ids and self.id not in ids:
            return False

        #: Filter hosts by asset ID.
        if asset_ids and self.asset_id not in asset_ids:
            return False

        #: Filter hosts by IP address and/or hostname.
        if locations and not edgescan.patterns.matches(self.locations, locations):
            return False

        #: Filter hosts by OS type.
        if os_types:
            os_types = [edgescan.platforms.parse_os_type(os_type) for os_type in os_types]
            if not edgescan.patterns.matches(self.os_type, os_types):
                return False

        #: Filter hosts by OS version.
        if os_versions and not edgescan.patterns.matches(self.os_version, os_versions):
            return False

        #: Filter hosts based on whether they're dead or alive.
        if alive is not None and alive != self.is_alive():
            return False

        #: Filter hosts based on when they were last seen.
        if (min_last_seen_time or max_last_seen_time) and \
                not edgescan.time.in_range(self.last_seen_time, min_last_seen_time, max_last_seen_time):
            return False
        return True

    def __hash__(self):
        return self.id
