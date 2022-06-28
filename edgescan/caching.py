import distutils.util
import os

TRUE = 1


def is_enabled() -> bool:
    v = os.getenv('EDGESCAN_ENABLE_CACHE', None)
    if v is None:
        return False
    return distutils.util.strtobool(v) == TRUE


def is_disabled() -> bool:
    return is_enabled() is False
