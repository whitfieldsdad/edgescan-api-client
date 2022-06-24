import datetime
from typing import List, Optional

import edgescan.time


def str_to_strs(data: Optional[str]) -> List[str]:
    if not data:
        return []
    return data.split(',')


def str_to_ints(data: Optional[str]) -> List[int]:
    return [int(v) for v in str_to_strs(data)]


def str_to_datetime(value: str) -> Optional[datetime.datetime]:
    return edgescan.time.to_datetime(value)
