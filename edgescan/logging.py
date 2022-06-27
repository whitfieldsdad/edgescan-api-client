from typing import Optional


def get_hint(**kwargs) -> Optional[str]:
    kwargs = dict((k, v) for (k, v) in kwargs.items() if v or isinstance(v, (int, float)))
    return ', '.join('{}: {}'.format(k, v) for (k, v) in kwargs.items())
