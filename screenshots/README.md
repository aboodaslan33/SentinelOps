# Screenshots Guide

This folder holds the images that make the SentinelOps portfolio readable at a glance. A
recruiter often looks at the screenshots before reading anything else, so they are worth doing
carefully.

> **MANUAL STEP.** These images must be captured from your running lab — they cannot be
> generated. Follow the shot list below.

---

## Redaction rules (read before capturing anything)

Before any image goes into the repository, remove or blur:

- real user names (use `labuser`, `lab-admin`, `svc-backup` — the lab names in this repo);
- any **public** IP address, and your real home/office network ranges (the lab uses
  `192.168.56.0/24`, which is a standard private range and safe to show);
- host names that identify you or a real organisation;
- Wazuh/OS passwords, API keys, licence keys, certificate content;
- browser bookmarks, other tabs, email, or anything personal in the window chrome.

Capture at a readable resolution (1600px+ wide), crop to the relevant panel, and save as PNG.
Keep the file names below so the README image links resolve.

> Tip: keep unredacted originals **out** of git — `.gitignore` already excludes
> `screenshots/unredacted/` and `*.raw.png`. Redact into the final filename only.

---

## Shot list

### 1. Wazuh Dashboard — overview
- **Open:** ☰ → *Dashboards* → `SentinelOps - SOC Overview` (or the default Wazuh overview).
- **Show:** the metric row (Total / Critical / High / Medium / Low), the alert timeline, and at
  least one populated table. Set the time picker to *Last 24 hours* and make sure it is visible.
- **Hide:** browser bookmarks/other tabs; any real host name in the agent list.
- **File:** `01-wazuh-dashboard-overview.png`

### 2. Connected Windows agent
- **Open:** ☰ → *Agents* (or *Endpoints Summary*).
- **Show:** `WIN-SOC-EP01` with status **Active** (green), agent version, and the OS.
- **Hide:** the agent's real registration IP if it reveals your home network (the lab IP
  `192.168.56.20` is fine).
- **File:** `02-agent-connected.png`

### 3. Sysmon logs arriving
- **Open:** ☰ → *Discover*, index `wazuh-alerts-*` (or the events index), query
  `data.win.system.providerName:"Microsoft-Windows-Sysmon"`.
- **Show:** several Sysmon events with `data.win.system.eventID` visible (1, 3, 11, etc.) and
  one row expanded to show `image` / `commandLine` / `parentImage`.
- **File:** `03-sysmon-logs.png`

### 4. Brute-force alert
- **Open:** *Discover*, query `rule.id:100101`.
- **Show:** the level-10 alert, the description containing the source IP, and the underlying
  4625 events. If you can, expand the alert JSON to show `rule.mitre.id: T1110.001`.
- **File:** `04-brute-force-alert.png`

### 5. PowerShell alert
- **Open:** *Discover*, query `rule.id:(100111 OR 100113)`.
- **Show:** the alert plus, in the expanded event, the decoded **4104 script block** text —
  this is the most impressive single screenshot in the set.
- **File:** `05-powershell-alert.png`

### 6. Account-creation alert
- **Open:** *Discover*, query `rule.id:(100120 OR 100121)`.
- **Show:** the new account name (`lab-svc-update`), the creator, and — if `100121` fired — the
  correlation description "added to a privileged group within 5 minutes".
- **File:** `06-account-creation-alert.png`

### 7. Suspicious-process alert
- **Open:** *Discover*, query `rule.id:(100131 OR 100134)`.
- **Show:** the recon-burst alert and/or the masquerading alert with `image` vs
  `originalFileName` visible in the expanded event.
- **File:** `07-suspicious-process-alert.png`

### 8. MITRE ATT&CK mapping
- **Open:** ☰ → *MITRE ATT&CK → Framework* (the built-in matrix), **or** the ATT&CK Navigator
  layer you exported (`documentation/mitre-attack-mapping.md` §4).
- **Show:** the matrix with detected techniques highlighted, or the "Techniques by frequency"
  bar chart.
- **File:** `08-mitre-attack-mapping.png`

### 9. Incident investigation
- **Open:** *Discover* during a real investigation — a saved search filtered to one host with
  columns `timestamp`, `rule.level`, `rule.description`, `targetUserName`, `ipAddress`, sorted by
  time — **or** a rendered view of one of the incident reports.
- **Show:** the analyst's working view: a timeline of related events for a single incident.
- **File:** `09-incident-investigation.png`

### 10. Final dashboard
- **Open:** your completed `SentinelOps - SOC Overview` dashboard **after** running all five
  simulations, so every panel has data.
- **Show:** a full, populated dashboard — metrics, timeline, top rules, MITRE, source IPs.
- **File:** `10-final-dashboard.png`

---

## Optional extra shots (nice to have)

| File | Content |
|---|---|
| `11-authentication-dashboard.png` | The Authentication dashboard (failed vs successful, top IPs) |
| `12-endpoint-activity-dashboard.png` | The Endpoint Activity dashboard (process ancestry table) |
| `13-sysmon-config-active.png` | `Sysmon64.exe -c` output showing the active config |
| `14-wazuh-logtest.png` | `wazuh-logtest` output showing a custom rule firing |
| `15-agent-ossec-log.png` | The agent `ossec.log` "Connected to the server" lines |

---

## How to reference these in the main README

The main [`README.md`](../README.md) has a Screenshots section that links to these files. Once
you drop the PNGs in here with the names above, those links resolve automatically — no other
edit needed.
