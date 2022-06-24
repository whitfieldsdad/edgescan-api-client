from dataclasses import dataclass
from typing import List, Any, Optional, Union
from edgescan.data.types.assessment import Assessment
from edgescan.data.types.license import License

import edgescan.patterns
import edgescan.time
import datetime

from edgescan.data.types.location_specifier import LocationSpecifier


@dataclass(frozen=True)
class Asset:
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
    def create_time(self) -> datetime.datetime:
        return self.created_at

    @property
    def update_time(self) -> datetime.datetime:
        return self.updated_at

    def matches(
            self,
            ids: Optional[List[int]] = None,
            names: Optional[List[str]] = None,
            tags: Optional[List[str]] = None,
            min_create_time: Optional[Union[str, int, float, datetime.datetime, datetime.date]] = None,
            max_create_time: Optional[Union[str, int, float, datetime.datetime, datetime.date]] = None,
            min_update_time: Optional[Union[str, int, float, datetime.datetime, datetime.date]] = None,
            max_update_time: Optional[Union[str, int, float, datetime.datetime, datetime.date]] = None,
            min_next_assessment_time: Optional[Union[str, int, float, datetime.datetime, datetime.date]] = None,
            max_next_assessment_time: Optional[Union[str, int, float, datetime.datetime, datetime.date]] = None,
            min_last_assessment_time: Optional[Union[str, int, float, datetime.datetime, datetime.date]] = None,
            max_last_assessment_time: Optional[Union[str, int, float, datetime.datetime, datetime.date]] = None,
            min_last_host_scan_time: Optional[Union[str, int, float, datetime.datetime, datetime.date]] = None,
            max_last_host_scan_time: Optional[Union[str, int, float, datetime.datetime, datetime.date]] = None) -> bool:

        if ids and self.id not in ids:
            return False

        if names and not edgescan.patterns.matches(self.name, names):
            return False

        if tags and set(self.tags).isdisjoint(tags):
            return False

        for timestamp, min_timestamp, max_timestamp in (
                (self.create_time, min_create_time, max_create_time),
                (self.update_time, min_update_time, max_update_time),
                (self.next_assessment_date, min_next_assessment_time, max_next_assessment_time),
                (self.last_assessment_date, min_last_assessment_time, max_last_assessment_time),
                (self.last_host_scan, min_last_host_scan_time, max_last_host_scan_time),
        ):
            if (min_timestamp or max_timestamp) and \
                    not edgescan.time.in_range(timestamp, min_timestamp, max_timestamp):
                return False
        return True

    def __hash__(self):
        return self.id
