import fnmatch
import glob
from typing import Union, Iterable


def matches(values: Union[str, Iterable[str]], patterns: Union[str, Iterable[str]] = None):
    values = _to_lowercase_strings(values)
    patterns = _to_lowercase_strings(patterns)

    for value in values:
        for pattern in patterns:
            if value == pattern or (glob.has_magic(pattern) and fnmatch.fnmatch(value, pattern)):
                return True
    return False


def _to_lowercase_strings(values: Union[str, Iterable[str]]):
    values = [values] if isinstance(values, str) else list(values)
    values = list(map(str.lower, values))
    return values
