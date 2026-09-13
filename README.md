# SentinelOps

### Windows Threat Detection, SIEM Monitoring & Incident Response Lab

<p>
  <img alt="SIEM" src="https://img.shields.io/badge/SIEM-Wazuh%204.x-2b6cb0">
  <img alt="Endpoint" src="https://img.shields.io/badge/Endpoint-Windows%2010%2F11%20%2B%20Sysmon-1a4971">
  <img alt="Framework" src="https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-c53030">
  <img alt="Detections" src="https://img.shields.io/badge/Detections-30%20rules%20%C2%B7%205%20scenarios-2f855a">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-b7791f">
</p>

> A complete, reproducible SOC Level 1 laboratory that simulates the security-monitoring
> environment of a small organisation — built to demonstrate practical Blue Team / SOC Analyst
> skills end to end, from log collection to incident documentation.

---

## Overview

SentinelOps is a self-contained Security Operations Center lab. A single Windows endpoint is
instrumented with **Sysmon** and PowerShell logging, its events are collected by a **Wazuh**
SIEM, and a set of **30 custom detection rules** turns that telemetry into alerts across five
realistic attack scenarios. Every alert is triaged, investigated and documented the way a SOC L1
analyst would, and every detection is mapped to **MITRE ATT&CK**.

The project is designed to be **realistic, professional, reproducible and safe**: all attack
simulation is performed by benign scripts inside an isolated host-only network, and every
document distinguishes laboratory data from real activity.

**Who this is for:** a fresh cybersecurity graduate applying for SOC Analyst L1, Junior SOC
Analyst, Cybersecurity Analyst or Security Operations Intern roles — as a portfolio piece that
can be demonstrated and defended in an interview.

---

## Objectives

- Stand up a working SIEM (Wazuh) and collect high-fidelity Windows endpoint telemetry.
- Practise **detection engineering**: baseline, write, test, tune and document detection rules.
- Build the five core SOC L1 skills: **log analysis, threat detection, alert triage, incident
  investigation, and incident response.**
- Map every detection to **MITRE ATT&CK** accurately.
- Produce the artefacts a real SOC produces: dashboards, playbooks and incident reports.
- Do all of the above **safely** and **honestly**, with clearly stated scope and limitations.

---

## Architecture

```
Windows Endpoint (WIN-SOC-EP01)
   Windows Security/System logs + Sysmon + PowerShell logging
        |
        v
Wazuh Agent  --- TCP/1514 (encrypted) --->  Wazuh Manager
                                              Decoders -> Rules -> Alerts
                                                    |
                                                    v
                                              Wazuh Indexer
                                                    |
                                                    v
                                              Wazuh Dashboard  --->  SOC L1 Analyst
```

Full diagram and design rationale: [`architecture/architecture.md`](architecture/architecture.md)
· rendered image: [`architecture/architecture.svg`](architecture/architecture.svg).

| Component | Host | OS | Lab IP |
|---|---|---|---|
| Wazuh (manager + indexer + dashboard) | `wazuh-mgr` | Ubuntu Server 22.04 LTS | `192.168.56.10` |
| Monitored endpoint | `WIN-SOC-EP01` | Windows 11 Pro | `192.168.56.20` |
| Attack simulator (optional) | `LAB-ATTACK01` | Windows 10 / Kali | `192.168.56.30` |

---

## Technologies

| Technology | Role | Version policy |
|---|---|---|
| **Wazuh** | SIEM / XDR — collection, rules, correlation, dashboards, ATT&CK | Current stable **4.x** via the official installation assistant |
| **Windows 10 / 11** | Monitored endpoint | Win 11 Pro 22H2 (Win 10 Pro also fine) |
| **Sysmon** | Rich endpoint telemetry (process, network, file, DNS, LSASS) | **v15+** (Sysinternals) |
| **Windows Event Logs** | Authentication, account, process, privilege events | Native |
| **PowerShell** | Script-block logging (4104) + safe simulation scripts | 5.1 / 7.x |
| **MITRE ATT&CK** | Detection mapping and coverage tracking | Enterprise, current |
| **Python** (optional) | Small helper utilities | 3.x |

> Rationale for each choice is in [`architecture/architecture.md`](architecture/architecture.md) §8.
> Always record the exact versions you install (`wazuh-control info`, `Sysmon64.exe -c`).

---

## Lab environment

A three-VM (or two-VM) lab on a **host-only** network — unreachable from the internet.
Full step-by-step build, with exact commands, expected output, verification and troubleshooting:

**[`documentation/installation.md`](documentation/installation.md)** — covers VM requirements,
network setup, Wazuh install, agent enrolment, audit policy, PowerShell logging, Sysmon,
log collection, end-to-end verification, and a snapshot/reset procedure.

---

## Detection scenarios

Five realistic SOC scenarios, 30 rules total ([`detection-rules/`](detection-rules/)):

| # | Scenario | Rules | MITRE | Doc |
|---|---|---|---|---|
| 1 | **Brute force / failed logins** | `100100`–`100104` | T1110, T1110.001, T1110.003 | [brute-force.md](detection-rules/brute-force.md) |
| 2 | **Suspicious PowerShell** | `100110`–`100115` | T1059.001, T1027.010, T1105 | [powershell.md](detection-rules/powershell.md) |
| 3 | **New account creation** | `100120`–`100123`, `100140` | T1136.001, T1098.007 | [account-creation.md](detection-rules/account-creation.md) |
| 4 | **Suspicious process execution** | `100130`–`100134` | T1082, T1087.001, T1218, T1036.003 | [suspicious-process.md](detection-rules/suspicious-process.md) |
| 5 | **Privilege escalation** | `100140`–`100145`, `100151` | T1098.007, T1548.002, T1053.005, T1543.003 | [privilege-escalation.md](detection-rules/privilege-escalation.md) |

Plus cross-cutting detections: log clearing (`100150`), audit-policy change (`100151`), Sysmon
tampering (`100152`) and LSASS access (`100153`). Each detection is documented with data source,
event IDs, the Wazuh rule explained line by line, severity, false positives, investigation steps
and recommended response. The deployable file is
[`detection-rules/local_rules.xml`](detection-rules/local_rules.xml).

Detection-engineering methodology (baseline → write → test → tune → document):
[`documentation/detection-engineering.md`](documentation/detection-engineering.md).

**Safe attack simulation:** all telemetry is produced by benign PowerShell scripts in
[`scripts/`](scripts/) — no malware, no real payloads, no external targets.

---

## MITRE ATT&CK mapping

Every detection is mapped to a verified ATT&CK technique. Nine of the fourteen Enterprise
tactics have at least one working detection; the gaps (lateral movement, exfiltration, etc.) are
stated honestly with the reason. Full table and coverage analysis:
**[`documentation/mitre-attack-mapping.md`](documentation/mitre-attack-mapping.md)**.

| Tactic | Example technique | Rule |
|---|---|---|
| Credential Access | T1110.001 Password Guessing · T1003.001 LSASS | `100101` · `100153` |
| Execution | T1059.001 PowerShell | `100111`, `100113` |
| Persistence | T1136.001 Local Account · T1053.005 Scheduled Task | `100120` · `100143` |
| Privilege Escalation | T1548.002 UAC Bypass · T1098.007 Groups | `100142` · `100140` |
| Defense Evasion | T1027.010 Obfuscation · T1070.001 Clear Logs | `100111` · `100150` |
| Discovery | T1082 / T1087.001 / T1033 / T1016 | `100131` |
| Command and Control | T1105 Ingress Tool Transfer | `100113`, `100132` |

---

## Dashboard

A professional Wazuh dashboard set — Overview (alert KPIs by severity), Authentication (failed
vs successful, top source IPs, targeted accounts), Endpoint Activity (process ancestry,
PowerShell, accounts), Timeline, and MITRE ATT&CK coverage. Every visualisation has exact
build instructions (type, index, aggregation, query):
**[`documentation/dashboard.md`](documentation/dashboard.md)**.

---

## Investigation workflow

A realistic SOC L1 workflow — **Alert → Triage → Validate → Investigate → Collect Evidence →
Determine Severity → Contain/Escalate → Document → Closure** — with, for each stage, what the
analyst checks, what evidence they collect, what questions they ask, and when they escalate or
close: **[`documentation/investigation-process.md`](documentation/investigation-process.md)**.

Incident-response process (NIST SP 800-61, scaled to a small org):
[`documentation/incident-response.md`](documentation/incident-response.md).

Operational, one-page **playbooks** for each scenario: [`playbooks/`](playbooks/).

---

## Incident reports

Five professional incident reports, using realistic lab data and following a consistent template
(summary, timeline, indicators, investigation, MITRE mapping, findings, response,
recommendations, lessons learned): **[`incidents/`](incidents/)**.

| Incident | Scenario | Severity | Status |
|---|---|---|---|
| [INC-2026-001](incidents/incident-001-brute-force.md) | Brute force | Medium | Contained |
| [INC-2026-002](incidents/incident-002-powershell.md) | PowerShell download cradle | High | Contained |
| [INC-2026-003](incidents/incident-003-account-creation.md) | Backdoor admin account | High | Eradicated |
| [INC-2026-004](incidents/incident-004-suspicious-process.md) | Recon + masquerading | High | Contained |
| [INC-2026-005](incidents/incident-005-privilege-escalation.md) | Privilege escalation | High | Eradicated |

---

## Screenshots

The ten recommended screenshots (and how to capture and redact them) are listed in
[`screenshots/README.md`](screenshots/README.md). Once captured, they render here:

| | | |
|---|---|---|
| ![Dashboard overview](screenshots/01-wazuh-dashboard-overview.png) | ![Agent connected](screenshots/02-agent-connected.png) | ![Sysmon logs](screenshots/03-sysmon-logs.png) |
| ![Brute force](screenshots/04-brute-force-alert.png) | ![PowerShell](screenshots/05-powershell-alert.png) | ![MITRE](screenshots/08-mitre-attack-mapping.png) |

*(Images appear once you add the PNG files — see the screenshots guide.)*

---

## Skills demonstrated

`SIEM (Wazuh)` · `Windows Security Monitoring` · `Sysmon` · `Windows Event Log Analysis` ·
`Log Collection` · `Detection Engineering` · `Threat Detection` · `Alert Triage` ·
`Incident Investigation` · `Incident Response` · `MITRE ATT&CK Mapping` · `Security Dashboards` ·
`Incident Documentation` · `PowerShell`

---

## Lessons learned

- **Telemetry quality decides detection quality.** Enabling Sysmon and PowerShell script-block
  logging did more for detection than any single rule — process ancestry and de-obfuscated
  script text are what make alerts actionable.
- **Correlation beats single events.** The highest-value alerts (successful logon after a brute
  force; a new account promoted to admin within minutes) come from linking events, not matching
  one.
- **Thresholds must be measured, not copied.** The current thresholds are first-draft values
  derived from assumed baselines; once the lab is built, a 48-hour baseline must confirm or
  retune them (a fixed correlation window is, by design, evaded by a slow attacker).
- **Field names and rule chaining are where custom rules fail.** Wazuh lowercases event fields
  and matches one rule per level — chaining on stable group names, verified with `wazuh-logtest`,
  is what makes a rule actually fire.
- **Honest scope is a strength.** Naming what the lab cannot see (AD, lateral movement,
  exfiltration) is more credible than claiming full coverage.

---

## Future improvements

- Add a **domain controller** to practise Active Directory attacks (Kerberoasting, DCSync).
- Add a **second endpoint** to detect **lateral movement** (the Sysmon config already collects
  the named-pipe and SMB telemetry for it).
- Add a **network sensor** (Suricata / Zeek) for network-based detections.
- Add **Wazuh Active Response** for automated containment.
- Add a correlation rule linking **privilege escalation → subsequent persistence**.
- Integrate a **threat-intelligence** feed for IOC enrichment.
- Add automated **alerting** (email / chat) to remove the manual dashboard-monitoring gap.

---

## Repository structure

```
SentinelOps/
├── README.md
├── LICENSE
├── .gitignore
├── architecture/          Architecture diagram + design rationale
├── detection-rules/       5 detection docs + deployable local_rules.xml (30 rules)
├── sysmon/                Sysmon config (commented) + install/tuning guide
├── incidents/             5 incident reports + template
├── playbooks/             5 SOC analyst playbooks
├── documentation/         Installation, detection engineering, investigation,
│                          incident response, dashboard, MITRE mapping
├── scripts/               Safe PowerShell simulation + read-only helper scripts
├── screenshots/           Screenshot capture guide (+ your PNGs)
└── career/                CV entry, LinkedIn text, 15 interview Q&A, portfolio checklist
```

---

## Getting started

1. Build the lab: [`documentation/installation.md`](documentation/installation.md).
2. Deploy the rules: [`detection-rules/README.md`](detection-rules/README.md).
3. Run a simulation: [`scripts/README.md`](scripts/README.md).
4. Investigate the alerts using the [playbooks](playbooks/) and the
   [investigation workflow](documentation/investigation-process.md).
5. Build the [dashboards](documentation/dashboard.md) and capture
   [screenshots](screenshots/README.md).
6. Work through the [portfolio checklist](career/portfolio-checklist.md).

---

## Disclaimer

**All security testing in this project was performed exclusively within an isolated laboratory
environment** consisting of virtual machines owned by the author on a private host-only network
with no connectivity to the internet, to any production system, to any real organisation, or to
any real user.

The attack-simulation scripts in this repository are **defensive testing tools**: they generate
the benign telemetry that a technique produces, so that detections can be validated. They contain
no malware, exploits, real payloads, persistence or destructive actions, and must only be run
against systems you own and are authorised to test. All data in the incident reports and
detection examples is **simulated laboratory data**, labelled as such.

This project is provided for **educational and portfolio purposes** under the [MIT License](LICENSE).
Do not use any content here to access, test or attack systems without explicit authorisation.
Unauthorised access to computer systems is illegal.
