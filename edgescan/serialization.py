import json
from json import JSONEncoder as _JSONEncoder

import dataclasses
import datetime
from typing import Any


class JSONEncoder(_JSONEncoder):
    def default(self, obj):
        if dataclasses.is_dataclass(obj):
            return dataclasses.asdict(obj)
        if isinstance(obj, (datetime.date, datetime.datetime)):
            return obj.isoformat()
        elif isinstance(obj, datetime.timedelta):
            return obj.total_seconds()
        elif isinstance(obj, set):
            return sorted(obj)
        else:
            return super().default(obj)


def to_json(value: Any):
    return json.dumps(value, cls=JSONEncoder)
