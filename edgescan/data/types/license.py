from typing import Optional
from dataclasses import dataclass

import datetime


@dataclass(frozen=True)
class License:
    id: int
    name: str
    license_type_id: int
    license_type_name: str
    asset_id: Optional[int]
    order_id: int
    start_date: datetime.datetime
    end_date: datetime.datetime
    expired: bool
    status: Optional[str]

    def is_expired(self) -> bool:
        return self.expired

    def __hash__(self):
        return self.id
