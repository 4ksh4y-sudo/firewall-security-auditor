from dataclasses import dataclass, field
from typing import List


@dataclass
class FirewallRule:
    rule_id: str
    name: str = ""
    enabled: bool = True
    action: str = "UNKNOWN"
    protocol: str = "ANY"
    source: str = "ANY"
    destination: str = "ANY"
    ports: List[int] = field(default_factory=list)
    direction: str = "ANY"
    source_interface: str = "ANY"
    destination_interface: str = "ANY"
    comment: str = ""
    source_platform: str = ""
