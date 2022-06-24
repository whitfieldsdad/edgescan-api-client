import datetime
from typing import Union, Optional

import dateutil.parser


def in_range(
        time: Union[str, int, float, datetime.datetime, datetime.date],
        min_time: Union[str, int, float, datetime.datetime, datetime.date, None] = None,
        max_time: Union[str, int, float, datetime.datetime, datetime.date, None] = None) -> bool:
    if time:
        time, min_time, max_time = map(lambda t: to_datetime(t) if t else None, (time, min_time, max_time))
        if min_time and time < min_time:
            return False
        if max_time and time > max_time:
            return False
    return True


def to_datetime(t: Union[str, int, float, datetime.date, datetime.datetime, None]) -> Optional[datetime.datetime]:
    if t is not None:
        t = _to_datetime(t)
        if t:
            return t.astimezone()


def _to_datetime(t: Union[str, int, float, datetime.date, datetime.datetime, None]) -> Optional[datetime.datetime]:
    if t is not None:
        if isinstance(t, datetime.datetime):
            return t
        elif isinstance(t, str):
            return dateutil.parser.parse(t)
        elif isinstance(t, (int, float)):
            return datetime.datetime.fromtimestamp(t)
        elif isinstance(t, datetime.datetime):
            return t
        elif isinstance(t, datetime.date):
            return datetime.datetime.combine(t, datetime.datetime.min.time())
        else:
            raise TypeError("Cannot convert {} to time".format(type(t).__name__))
