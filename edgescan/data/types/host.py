from dataclasses import dataclass
from typing import Optional, List, Union

import edgescan.patterns
import edgescan.platforms
import edgescan.time
import ipaddress
import datetime

from edgescan.type_hints import TIME


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
    def update_time(self) -> TIME:
        return self.updated_at

    @property
    def last_seen_time(self) -> TIME:
        return self.updated_at

    def is_alive(self) -> bool:
        return self.status == 'alive'

    def __hash__(self):
        return self.id
