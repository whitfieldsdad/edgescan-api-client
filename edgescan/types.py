import dataclasses
from typing import Any


def dict_to_dataclass(data: Any, cls: Any) -> Any:
    fields = dataclasses.fields(cls)
    non_init_fields = frozenset((f.name for f in fields if f.init is False))
    if non_init_fields:
        for k in non_init_fields:
            if k in data:
                del data[k]

    fields = {f.name for f in fields}
    data = dict(((k, v) for (k, v) in data.items() if k in fields))
    return cls(**data)
