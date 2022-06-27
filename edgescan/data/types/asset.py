from dataclasses import dataclass
from typing import List, Any, Optional, Union
from edgescan.data.types.assessment import Assessment
from edgescan.data.types.base import Object
from edgescan.data.types.license import License

import datetime

from edgescan.data.types.location_specifier import LocationSpecifier
from edgescan.type_hints import TIME


@dataclass(frozen=True)
class Asset(Object):
    id: int
    asset_status: str
    authenticated: bool
    active_license: License
    blocked_status: str
    created_at: datetime.datetime
    current_assessment: Assessment
    host_count: int
    hostname: str
    last_assessment_date: datetime.datetime
    last_host_scan: datetime.datetime
    linked_assets: List[Any]
    location_specifiers: List[LocationSpecifier]
    name: str
    network_access: str
    next_assessment_date: Optional[datetime.datetime]
    pci_enabled: Optional[bool]
    priority: int
    tags: List[str]
    targeting_mode: str
    type: str
    updated_at: datetime.datetime

    @property
    def locations(self) -> List[LocationSpecifier]:
        return self.location_specifiers

    @property
    def create_time(self) -> TIME:
        return self.created_at

    @property
    def update_time(self) -> TIME:
        return self.updated_at
