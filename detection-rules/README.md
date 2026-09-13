# Detection Rules — Index

All rules in this folder are **laboratory detections** written for Wazuh 4.x and tested against
a single Windows 11 endpoint running Sysmon.

## Files

| File | Detection | Rule IDs | Primary MITRE technique |
|---|---|---|---|
| [`brute-force.md`](brute-force.md) | SO-DET-001 — Brute force / failed authentication | 100100–100104 | T1110 |
| [`powershell.md`](powershell.md) | SO-DET-002 — Suspicious PowerShell execution | 100110–100115 | T1059.001 |
| [`account-creation.md`](account-creation.md) | SO-DET-003 — Unexpected local account creation | 100120–100123, 100140 | T1136.001 |
| [`suspicious-process.md`](suspicious-process.md) | SO-DET-004 — Suspicious process execution / recon | 100130–100134 | T1082, T1218 |
| [`privilege-escalation.md`](privilege-escalation.md) | SO-DET-005 — Privilege escalation | 100140–100145, 100151 | T1548.002, T1098.007 |
| [`local_rules.xml`](local_rules.xml) | **The deployable rule file** — all 30 rules | 100100–100153 | — |

Cross-cutting rules (`100150` log cleared, `100151` audit policy changed, `100152` Sysmon
tampering, `100153` LSASS access) are documented inline in `local_rules.xml`.

## Severity model

| Wazuh level | SOC severity | Analyst action |
|---|---|---|
| 0–3 | Informational | Context only — never ticketed on its own |
| 4–7 | Low | Review during the shift |
| 8–11 | Medium | Triage within 1 hour |
| 12–14 | High | Triage immediately |
| 15 | Critical | Confirmed compromise — escalate at once |

## Deployment (MANUAL STEP — on the Wazuh manager)

```bash
# 1. Back up the existing file
sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak

# 2. Install this repository's rules
sudo cp detection-rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
sudo chmod 660 /var/ossec/etc/rules/local_rules.xml

# 3. Validate BEFORE restarting (catches XML and rule syntax errors)
sudo /var/ossec/bin/wazuh-logtest -t

# 4. Apply
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager --no-pager

# 5. Confirm the rules loaded
sudo grep -iE "rule|error" /var/ossec/logs/ossec.log | tail -30
```

Expected: `wazuh-logtest -t` exits without error and `ossec.log` shows no
`Error loading the rules` lines. If a MITRE technique ID is not present in your Wazuh build's
ATT&CK database, `ossec.log` will say so — update Wazuh or remove that `<id>` element.

## Testing a rule

```bash
sudo /var/ossec/bin/wazuh-logtest
# Paste a full JSON Windows eventchannel line captured from
# /var/ossec/logs/archives/archives.json, then read the output:
#   **Phase 1: Completed pre-decoding / Phase 2: decoder  / Phase 3: rule id
```

The full methodology — baseline, write, test, tune, document — is in
[`/documentation/detection-engineering.md`](../documentation/detection-engineering.md).
