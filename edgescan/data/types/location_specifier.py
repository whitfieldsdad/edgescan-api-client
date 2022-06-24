from dataclasses import dataclass

IP = 'ip'
CIDR = 'cidr'
BLOCK = 'block'


@dataclass(frozen=True)
class LocationSpecifier:
    location: str
    location_type: str

    def is_ip(self) -> bool:
        return self.location_type == IP

    def is_ip_range(self) -> bool:
        return self.location_type == BLOCK

    def is_cidr(self) -> bool:
        return self.location_type == CIDR
