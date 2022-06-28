from typing import Optional

import edgescan.patterns
import platform
import struct

WINDOWS = 'windows'
LINUX = 'linux'
DARWIN = 'darwin'
BSD = 'bsd'
SOLARIS = 'solaris'
ANDROID = 'android'
OTHER = 'other'

OS_TYPE = platform.system()
OS_VERSION = platform.version()
OS_BITNESS = 8 * struct.calcsize("P")


def get_os_type() -> str:
    return OS_TYPE


def get_os_version() -> str:
    return OS_VERSION


def get_os_bitness() -> int:
    return OS_BITNESS


def is_windows() -> bool:
    return OS_TYPE.lower() == WINDOWS


def is_linux() -> bool:
    return OS_TYPE.lower() == LINUX


def is_darwin() -> bool:
    return OS_TYPE.lower() == DARWIN


def parse_os_type(os_type: Optional[str]) -> Optional[str]:
    if os_type is None:
        return None

    if edgescan.patterns.matches(os_type, patterns=[
        '*microsoft*', '*windows*', '*cygwin*', '*mingw*', '*msys*', '*dos*'
    ]):
        return WINDOWS

    elif edgescan.patterns.matches(os_type, patterns=[
        '*linux*', '*ubuntu*', '*rhel*', '*red*hat*', '*centos*', '*debian*', '*gentoo*', '*opensuse*', '*sles*',
    ]):
        return LINUX

    elif edgescan.patterns.matches(os_type, patterns=['*darwin*', '*Apple iOS*']):
        return DARWIN

    elif edgescan.patterns.matches(os_type, patterns=['*FreeBSD*', '*OpenBSD*', '*pfsense*']):
        return BSD

    elif edgescan.patterns.matches(os_type, patterns='*solaris*'):
        return SOLARIS

    return OTHER
