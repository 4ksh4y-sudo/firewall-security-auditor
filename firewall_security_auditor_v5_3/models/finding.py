from dataclasses import dataclass


@dataclass
class Finding:
    severity: str
    rule_id: str
    title: str
    description: str
    recommendation: str
