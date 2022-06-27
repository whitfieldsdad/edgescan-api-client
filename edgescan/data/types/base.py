from dataclasses import dataclass
from typing import Optional

from edgescan.type_hints import TIME

import edgescan.time


@dataclass(frozen=True)
class Object(dict):
    @property
    def create_time(self) -> TIME:
        raise NotImplementedError()

    @property
    def update_time(self) -> TIME:
        raise NotImplementedError()

    def in_timeframe(
            self,
            min_create_time: Optional[TIME] = None, max_create_time: Optional[TIME] = None,
            min_update_time: Optional[TIME] = None, max_update_time: Optional[TIME] = None) -> bool:

        for t, min_t, max_t in [
            [self.create_time, min_create_time, max_create_time],
            [self.update_time, min_update_time, max_update_time],
        ]:
            if (min_t or max_t) is not None:
                if t is None or not edgescan.time.in_range(t, min_t, max_t):
                    return False
        return True
