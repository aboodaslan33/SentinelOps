# Incident Response Process

How SentinelOps handles a confirmed security incident, aligned to the six-phase model in
**NIST SP 800-61** (Computer Security Incident Handling Guide) and scaled to a small
organisation with a single SOC L1 analyst.

```
  1. PREPARATION  ->  2. DETECTION & ANALYSIS  ->  3. CONTAINMENT
                                                        |
  6. LESSONS LEARNED  <-  5. RECOVERY  <-  4. ERADICATION
```

> This is a laboratory process document. It describes how the lab operates and what a real
> small-organisation process would look like — it does not describe experience responding to
> incidents in a production environment.

---

## Phase 1 — Preparation

Everything that must exist **before** an incident.

| Area | What SentinelOps has in place |
|---|---|
| **Visibility** | Wazuh agent on the endpoint; Security, System, Application, Sysmon, PowerShell and Task Scheduler channels collected |
| **Detection content** | 30 custom rules covering 5 scenarios, each documented and MITRE-mapped |
| **Baseline** | 48-hour measured baseline of normal activity (see `detection-engineering.md` §4) |
| **Playbooks** | Five step-by-step playbooks in [`/playbooks`](../playbooks) |
| **Documentation templates** | Incident report template used by all five reports in [`/incidents`](../incidents) |
| **Asset inventory** | Host names, IPs, roles and owners recorded in [`architecture.md`](../architecture/architecture.md) |
| **Recovery capability** | Hypervisor snapshots at four defined points |
| **Contact path** | Single-analyst lab: escalation path documented below |

**Preparation gaps in this lab, stated honestly:** no backup/restore testing of user data, no
out-of-band communications plan, no legal/HR escalation path, no 24×7 coverage, no threat-intel
feed. These are real requirements in a production SOC and are listed as future improvements.

---

## Phase 2 — Detection and analysis

Fully covered by the SOC L1 workflow in
[`investigation-process.md`](investigation-process.md). Phase 2 ends with a written answer to
four questions:

1. **What happened?** (behaviour, technique, MITRE ID)
2. **What is affected?** (hosts, accounts, data)
3. **Is it still happening?** (active vs. historical)
4. **How confident am I, and on what evidence?**

**Declaring an incident.** In this lab an alert becomes an *incident* when any of the following
is true:

* attacker-controlled code executed on the endpoint;
* an account was created, modified or successfully authenticated without authorisation;
* privileges were escalated;
* persistence was established (account, task, service, registry autostart);
* logging or security tooling was tampered with;
* more than one host shows the same behaviour.

Everything else stays an alert and is closed in the ticket.

---

## Phase 3 — Containment

**Objective: stop the damage spreading without destroying the evidence you will need.**

### Short-term containment (minutes)

| Action | Command (lab) | Trade-off |
|---|---|---|
| Isolate the host from the network | Detach the virtual NIC, or apply an EDR isolation policy | Ends attacker access instantly; also ends your remote visibility |
| Disable the compromised account | `Disable-LocalUser -Name "<account>"` | **Disable, never delete** — the SID is needed to attribute later events |
| Block the source IP | `New-NetFirewallRule -DisplayName "IR-block-<ticket>" -Direction Inbound -RemoteAddress <ip> -Action Block` | Attacker may already have another route |
| Terminate the malicious process | `Stop-Process -Id <pid> -Force` | Capture image path, command line, parent and hash **first** |
| Suspend a scheduled task | `Disable-ScheduledTask -TaskName "<name>"` | Export the task XML before disabling |

### Evidence preservation before eradication

```powershell
# MANUAL STEP - run before changing anything you do not have to change
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -ItemType Directory -Path "C:\Lab\Evidence\$ts" -Force | Out-Null

wevtutil epl Security  "C:\Lab\Evidence\$ts\Security.evtx"
wevtutil epl System    "C:\Lab\Evidence\$ts\System.evtx"
wevtutil epl "Microsoft-Windows-Sysmon/Operational"     "C:\Lab\Evidence\$ts\Sysmon.evtx"
wevtutil epl "Microsoft-Windows-PowerShell/Operational" "C:\Lab\Evidence\$ts\PowerShell.evtx"

Get-Process        | Export-Csv "C:\Lab\Evidence\$ts\processes.csv" -NoTypeInformation
Get-NetTCPConnection | Export-Csv "C:\Lab\Evidence\$ts\connections.csv" -NoTypeInformation
Get-LocalUser      | Export-Csv "C:\Lab\Evidence\$ts\localusers.csv" -NoTypeInformation
Get-ScheduledTask  | Export-Csv "C:\Lab\Evidence\$ts\tasks.csv" -NoTypeInformation

Get-ChildItem "C:\Lab\Evidence\$ts" | Get-FileHash -Algorithm SHA256 |
    Export-Csv "C:\Lab\Evidence\$ts\hashes.csv" -NoTypeInformation
```

Take a **hypervisor snapshot** of the running VM before making any change — it preserves memory
and disk state in one step and is the closest thing a lab has to forensic imaging.

### Long-term containment (hours)

Applied while a rebuild is planned: patch the exploited weakness, reset every credential that
touched the host, tighten the firewall rule set, apply the tuning/hardening that came out of
the investigation.

---

## Phase 4 — Eradication

Remove the attacker's access and artefacts completely.

| Artefact | Removal (after evidence capture) |
|---|---|
| Backdoor account | `Remove-LocalUser -Name "<account>"` (after it has been disabled and documented) |
| Privileged group membership | `Remove-LocalGroupMember -Group "Administrators" -Member "<account>"` |
| Scheduled task | `Unregister-ScheduledTask -TaskName "<name>" -Confirm:$false` |
| Malicious service | `sc.exe delete "<service>"` |
| Registry autostart | `Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "<value>"` |
| Dropped files | Delete after hashing and recording the path |
| Compromised credentials | Reset **every** account used on the host, including any cached domain credentials |

**Eradication verification:**

```powershell
Get-LocalUser | Where-Object Enabled -eq $true
Get-LocalGroupMember -Group "Administrators"
Get-ScheduledTask | Where-Object { $_.Author -notlike "Microsoft*" } | Select TaskName, Author
Get-CimInstance Win32_Service | Where-Object PathName -notlike 'C:\Windows\*' | Select Name, PathName
Start-MpScan -ScanType FullScan
```

> **When SYSTEM or administrative privilege was achieved, the honest answer is rebuild.**
> You cannot prove a host is clean after an attacker held SYSTEM. Cleaning is an acceptable
> business decision on a low-value asset, but it must be recorded as a risk acceptance, not
> presented as remediation.

---

## Phase 5 — Recovery

Return the system to production safely and confirm the threat does not return.

1. Restore from a known-good snapshot or rebuild from a trusted image.
2. Reapply all hardening **before** reconnecting to the network (audit policy, PowerShell
   logging, Sysmon, Wazuh agent, patching).
3. Reset all credentials associated with the host.
4. Reconnect, then verify: agent Active, telemetry flowing, all detections functional.
5. **Monitor with heightened sensitivity for at least 7 days**, specifically watching for the
   IOCs from the incident and for re-infection from the same vector.
6. Confirm with the user that the system works as expected.

**Recovery exit criteria:** no IOC activity for the monitoring window, all detections verified
working, the root-cause weakness remediated, and the asset owner has signed off.

---

## Phase 6 — Lessons learned

Held within five working days of closure. Six questions, honestly answered:

| Question | Purpose |
|---|---|
| What happened, as a timeline? | Shared factual baseline |
| How was it detected, and how long did detection take? | Measure **dwell time** |
| What worked in the response? | Keep doing it |
| What was slow, missing or wrong? | Fix it |
| Which detection gaps did this reveal? | New detection content |
| Which hardening measure would have prevented it? | Preventive control |

**Metrics tracked in this lab**

| Metric | Definition | Target |
|---|---|---|
| MTTD — mean time to detect | First malicious event → alert generated | < 5 minutes |
| MTTT — mean time to triage | Alert generated → analyst starts work | < 15 min (P1) |
| MTTR — mean time to respond | Alert generated → containment complete | < 1 hour (P1) |
| False positive rate | FP alerts ÷ total alerts | < 20 % |
| Detection coverage | ATT&CK techniques with a working detection | Tracked in the MITRE matrix |

Every lessons-learned session must produce at least one concrete deliverable: a new or tuned
rule, a playbook update, or a hardening change with an owner and a date.

---

## Escalation matrix (lab)

| Level | Role | Handles | Example |
|---|---|---|---|
| **L1** | SOC Analyst (this lab) | Triage, validation, investigation, documentation, containment within mandate | Failed brute force, false positives, single-host recon |
| **L2** | Senior analyst / IR | Confirmed compromise, multi-host activity, forensics, threat hunting | Successful brute force, privilege escalation, credential access |
| **L3 / Management** | IT lead, business owner | Business decisions: isolation of production systems, rebuild, notification | Service-affecting containment, data loss |
| **External** | IR retainer, law enforcement, regulator | Major breach, legal obligations | Confirmed data exfiltration, ransomware |

**Escalate immediately, without completing the investigation, when:** credentials were
confirmed compromised, an attacker reached SYSTEM/administrator, more than one host is
affected, data staging or exfiltration is suspected, ransomware indicators appear, or the
activity involves a business-critical system.

---

## Communication

| Audience | What they need | Example |
|---|---|---|
| **Technical (L2/IR)** | Full detail: rule IDs, event IDs, hashes, command lines, timeline | "Rule 100121 at 09:14:33 UTC: `lab-svc-update` added to Administrators by `labuser` (logon ID 0x3E7A1, type 3 from 192.168.56.30)." |
| **IT / asset owner** | What to do and when | "WIN-SOC-EP01 is isolated. Do not reconnect it until IR confirms. The user's password has been reset." |
| **Management** | Impact, status, decision needed | "One workstation affected. Contained at 09:31 UTC. No data loss identified. Rebuild recommended — needs approval." |
| **Users** | Plain language, no jargon, no blame | "We have locked your account as a precaution and will contact you to set a new password." |

Never speculate publicly about attribution or impact before evidence supports it. "We are
investigating" is always a better answer than a guess you have to retract.
