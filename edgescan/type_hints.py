import datetime
from typing import Iterable, Union

INTS = Iterable[int]
STRS = Iterable[str]
DATE = datetime.date
TIME = datetime.datetime
TIMESTAMP = Union[str, int, float, DATE, TIME]
BOOL = bool
NUMS = Union[int, float]
ANY = Union[str, DATE, TIME, bool, int, float]
