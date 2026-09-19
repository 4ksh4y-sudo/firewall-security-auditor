import json
from models.rule import FirewallRule
from parsers.base import FirewallParser


class GenericJSONParser(FirewallParser):
    def parse(self, filename):
        with open(filename, "r", encoding="utf-8") as file:
            data = json.load(file)

        rules = []
        for index, item in enumerate(data.get("rules", []), start=1):
            ports = item.get("ports", [])
            if isinstance(ports, int):
                ports = [ports]

            rules.append(
                FirewallRule(
                    rule_id=str(item.get("id", index)),
                    name=item.get("name", ""),
                    enabled=item.get("enabled", True),
                    action=str(item.get("action", "UNKNOWN")).upper(),
                    protocol=str(item.get("protocol", "ANY")).upper(),
                    source=item.get("source", "ANY"),
                    destination=item.get("destination", "ANY"),
                    ports=ports,
                    direction=str(item.get("direction", "ANY")).upper(),
                    source_interface=item.get("source_interface", "ANY"),
                    destination_interface=item.get("destination_interface", "ANY"),
                    comment=item.get("comment", ""),
                    source_platform=item.get("source_platform", "Generic JSON")
                )
            )
        return rules
