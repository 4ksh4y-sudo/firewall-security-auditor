from models.finding import Finding

MANAGEMENT_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    5985: "WinRM",
    5986: "WinRM HTTPS",
}

DEFAULT_PUBLIC_PORTS = {80, 443}


def is_any(value):
    return str(value).strip().upper() in {"ANY", "*", "0.0.0.0/0", "::/0"}


def signature(rule):
    return (
        rule.action.upper(),
        rule.protocol.upper(),
        str(rule.source).upper(),
        str(rule.destination).upper(),
        tuple(sorted(rule.ports)),
        rule.direction.upper()
    )


def analyze_rules(rules):
    findings = []

    # Individual rule checks
    for rule in rules:
        if not rule.enabled:
            findings.append(Finding(
                "LOW", rule.rule_id, "Disabled Rule",
                f"Rule '{rule.name or rule.rule_id}' is disabled.",
                "Remove obsolete rules when they are confirmed to be unnecessary."
            ))
            continue

        if rule.action.upper() == "ALLOW":
            if is_any(rule.source) and is_any(rule.destination):
                if not rule.ports:
                    findings.append(Finding(
                        "HIGH", rule.rule_id, "Broad Allow Rule",
                        f"Rule '{rule.name or rule.rule_id}' allows traffic from any source to any destination with no port restriction.",
                        "Restrict source, destination, protocol, and ports to the minimum required scope."
                    ))

            management = [
                MANAGEMENT_PORTS[p]
                for p in rule.ports
                if p in MANAGEMENT_PORTS
            ]
            if is_any(rule.source) and management:
                findings.append(Finding(
                    "CRITICAL", rule.rule_id, "Unrestricted Management Access",
                    f"Rule '{rule.name or rule.rule_id}' permits {', '.join(management)} from an unrestricted source.",
                    "Restrict administrative services to authorized management networks or hosts."
                ))

            if len(rule.ports) > 20:
                findings.append(Finding(
                    "MEDIUM", rule.rule_id, "Broad Port Set",
                    f"Rule '{rule.name or rule.rule_id}' contains {len(rule.ports)} explicit ports.",
                    "Review whether every permitted port is required."
                ))

            if 23 in rule.ports and is_any(rule.source):
                findings.append(Finding(
                    "HIGH", rule.rule_id, "Unrestricted Telnet",
                    "Telnet is permitted from an unrestricted source.",
                    "Disable Telnet where possible and use an encrypted administrative protocol."
                ))

    # Duplicate checks
    seen = {}
    for rule in rules:
        if not rule.enabled:
            continue
        sig = signature(rule)
        if sig in seen:
            findings.append(Finding(
                "MEDIUM",
                rule.rule_id,
                "Duplicate Rule",
                f"Rule {rule.rule_id} duplicates rule {seen[sig]}.",
                "Review and consolidate duplicate rules if they are not required."
            ))
        else:
            seen[sig] = rule.rule_id

    # Conservative shadowing heuristic:
    # only flag an earlier enabled ALLOW ANY-source/ANY-destination rule
    # with no ports as potentially shadowing a later rule in an ordered policy.
    for i, earlier in enumerate(rules):
        if not earlier.enabled or earlier.action.upper() != "ALLOW":
            continue
        if not (is_any(earlier.source) and is_any(earlier.destination) and not earlier.ports):
            continue

        for later in rules[i + 1:]:
            if not later.enabled:
                continue
            if later.action.upper() in {"DENY", "DROP", "REJECT"}:
                findings.append(Finding(
                    "HIGH",
                    later.rule_id,
                    "Potentially Shadowed Rule",
                    f"Rule {later.rule_id} follows broad allow rule {earlier.rule_id} and may never be evaluated on ordered firewalls.",
                    "Verify rule-processing order and whether the later rule is reachable."
                ))

    return findings
