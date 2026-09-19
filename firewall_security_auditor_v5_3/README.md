# Firewall Security Auditor V5.2

A defensive, read-only prototype for authorized security auditing.

## Features

- TCP connectivity audit
- Firewall policy import through normalized JSON
- Broad-rule detection
- Unrestricted management-service detection
- Telnet exposure detection
- Duplicate-rule detection
- Conservative potential-shadowing heuristic
- Disabled-rule reporting
- GUI dashboard
- Text report generation

## Run

```powershell
python main.py
```

Use the **LOAD SAMPLE** button to test the policy analyzer.

## Network audit

Use only against systems you own or are explicitly authorized to assess.

Example target:

```text
127.0.0.1
```

Example ports:

```text
22,80,443,3389
```

## Policy import

The generic JSON format is:

```json
{
  "rules": [
    {
      "id": 1,
      "name": "Allow HTTPS",
      "enabled": true,
      "action": "ALLOW",
      "source": "ANY",
      "destination": "ANY",
      "protocol": "TCP",
      "ports": [443],
      "direction": "IN"
    }
  ]
}
```

## Important limitations

This project does not exploit, bypass, modify, or disable firewalls.

Configuration-only analysis cannot prove that credentials were stolen, a host is compromised, tunneling occurred, or a rule is unused. Those require additional authorized evidence such as logs, flow data, endpoint telemetry, or vulnerability intelligence.

The potential-shadowing check is deliberately conservative and should be verified against the target firewall's actual rule-processing semantics.


## V5.3 GUI Refresh
- SOC-style dark dashboard
- Sidebar navigation
- Risk index and finding cards
- Improved network audit controls
- Severity-aware findings tables
- Refreshed report workspace
- Existing defensive/read-only scanner and analyzer logic preserved
