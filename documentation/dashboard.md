# Wazuh Dashboard — Build Guide

How to build the SentinelOps SOC dashboard, panel by panel.

> **MANUAL STEP.** Dashboards are built in the Wazuh Dashboard web interface; there is nothing
> to install from this repository. Every panel below lists the exact visualisation type, index
> pattern, aggregation and query to use. Wazuh Dashboard is based on OpenSearch Dashboards, so
> the menu wording may differ very slightly between releases — the aggregations do not.

---

## 0. Before you start

| Item | Value |
|---|---|
| URL | `https://192.168.56.10` |
| Index pattern | `wazuh-alerts-*` |
| Time zone | UTC (set under *Dashboards Management → Advanced settings → `dateFormat:tz`*) |
| Default time range | Last 24 hours |
| Query language | DQL (the default in the search bar) |

**Confirm the index pattern exists:**
☰ → *Dashboards Management* → *Index patterns*. If `wazuh-alerts-*` is missing, create it with
`timestamp` as the time field.

**Where visualisations are created:**
☰ → *Visualize* → **Create visualization** → pick the type → choose source `wazuh-alerts-*`.

**Where they are assembled:**
☰ → *Dashboards* → **Create dashboard** → *Add from library* → select your saved
visualisations → arrange → **Save** as `SentinelOps - SOC Overview`.

### The field names you will use constantly

| Field | Contains |
|---|---|
| `rule.level` | Wazuh severity 0–15 |
| `rule.id` | Rule that fired |
| `rule.description` | Human-readable alert title |
| `rule.groups` | Rule groups (e.g. `authentication_failed`) |
| `rule.mitre.id` / `rule.mitre.technique` / `rule.mitre.tactic` | ATT&CK mapping |
| `agent.name` | Endpoint that generated the alert |
| `data.win.system.eventID` | Windows / Sysmon event ID |
| `data.win.eventdata.targetUserName` | Account targeted |
| `data.win.eventdata.subjectUserName` | Account performing the action |
| `data.win.eventdata.ipAddress` | Source IP of a logon |
| `data.win.eventdata.image` / `parentImage` / `commandLine` | Process telemetry |
| `timestamp` | Event time |

> Aggregations require a **keyword** field. If a field does not appear in the "Field" dropdown,
> try `<field>.keyword` (for example `rule.description.keyword`), or refresh the index pattern
> field list under *Index patterns → wazuh-alerts-\* → Refresh*.

---

## Dashboard 1 — Overview

**Purpose:** the first screen an analyst opens. Answers "how busy am I, and how bad is it?"

### Panel 1.1 — Total Alerts

| Setting | Value |
|---|---|
| Type | **Metric** |
| Source | `wazuh-alerts-*` |
| Metric | Aggregation: **Count** |
| Custom label | `Total Alerts` |
| Query | *(empty — all alerts)* |
| Save as | `SO - Total Alerts` |

### Panels 1.2–1.5 — Alerts by severity

Create four **Metric** visualisations, identical except for the query in the search bar:

| Panel | Search bar query (DQL) | Custom label | Colour |
|---|---|---|---|
| Critical | `rule.level >= 15` | `Critical` | Red |
| High | `rule.level >= 12 and rule.level <= 14` | `High` | Orange |
| Medium | `rule.level >= 8 and rule.level <= 11` | `Medium` | Yellow |
| Low | `rule.level >= 4 and rule.level <= 7` | `Low` | Green |

For each: *Create visualization → Metric → Count →* type the query in the search bar *→ Save*
as `SO - Alerts <severity>`.

> Colour is set under *Options → Ranges* in the Metric visualisation, or left default. The
> severity bands match the model documented in `/detection-rules/README.md`.

### Panel 1.6 — Alert severity distribution

| Setting | Value |
|---|---|
| Type | **Pie** |
| Metric | Count |
| Bucket | *Split slices* → Terms → field `rule.level` → Size 10 → Order by Count, descending |
| Save as | `SO - Severity Distribution` |

### Panel 1.7 — Top 10 rules fired

| Setting | Value |
|---|---|
| Type | **Data table** |
| Metric | Count |
| Bucket | *Split rows* → Terms → `rule.description` (or `rule.description.keyword`) → Size 10 |
| Optional second bucket | *Split rows* → Terms → `rule.level` → Size 1 |
| Save as | `SO - Top Rules` |

### Panel 1.8 — Alerts by agent

| Setting | Value |
|---|---|
| Type | **Horizontal bar** |
| Y-axis | Count |
| X-axis bucket | Terms → `agent.name` → Size 10 |
| Save as | `SO - Alerts by Agent` |

---

## Dashboard 2 — Authentication

**Purpose:** answers "is anyone trying to get in, and did they succeed?"

### Panel 2.1 — Failed login attempts (count)

| Setting | Value |
|---|---|
| Type | **Metric** |
| Query | `data.win.system.eventID: "4625"` |
| Custom label | `Failed Logons (4625)` |
| Save as | `SO - Failed Logons` |

### Panel 2.2 — Successful logins (count)

| Setting | Value |
|---|---|
| Type | **Metric** |
| Query | `data.win.system.eventID: "4624"` |
| Custom label | `Successful Logons (4624)` |
| Save as | `SO - Successful Logons` |

### Panel 2.3 — Top source IPs

| Setting | Value |
|---|---|
| Type | **Data table** |
| Query | `data.win.system.eventID: "4625"` |
| Metric | Count |
| Bucket | *Split rows* → Terms → `data.win.eventdata.ipAddress` → Size 10 |
| Save as | `SO - Top Source IPs (failed)` |

### Panel 2.4 — Targeted accounts

| Setting | Value |
|---|---|
| Type | **Vertical bar** |
| Query | `data.win.system.eventID: "4625"` |
| Y-axis | Count |
| X-axis | Terms → `data.win.eventdata.targetUserName` → Size 10 |
| Save as | `SO - Targeted Accounts` |

### Panel 2.5 — Failed vs successful over time

| Setting | Value |
|---|---|
| Type | **Area** (or Line) |
| Query | `data.win.system.eventID: ("4624" or "4625")` |
| Y-axis | Count |
| X-axis bucket | *Date histogram* → `timestamp` → interval **Auto** |
| Split series | Terms → `data.win.system.eventID` → Size 2 |
| Save as | `SO - Auth Timeline` |

> **How to read it:** a tall red (4625) spike with no matching 4624 is a *failed* brute force.
> A 4625 spike immediately followed by a 4624 from the same IP is the shape that must be
> escalated — and is exactly what rule `100102` alerts on automatically.

### Panel 2.6 — Logon types

| Setting | Value |
|---|---|
| Type | **Pie** |
| Query | `data.win.system.eventID: "4624"` |
| Bucket | Terms → `data.win.eventdata.logonType` → Size 10 |
| Save as | `SO - Logon Types` |

Assemble as dashboard `SentinelOps - Authentication`.

---

## Dashboard 3 — Endpoint Activity

**Purpose:** answers "what is running on my endpoints?"

### Panel 3.1 — Process creation volume over time

| Setting | Value |
|---|---|
| Type | **Line** |
| Query | `data.win.system.eventID: "1" and data.win.system.providerName: "Microsoft-Windows-Sysmon"` |
| Y-axis | Count |
| X-axis | Date histogram → `timestamp` |
| Save as | `SO - Process Creation Timeline` |

### Panel 3.2 — PowerShell activity

| Setting | Value |
|---|---|
| Type | **Data table** |
| Query | `rule.id: (100110 or 100111 or 100112 or 100113 or 100114 or 100115)` |
| Buckets | *Split rows* → Terms → `rule.description` → Size 10; then Terms → `agent.name` → Size 5 |
| Save as | `SO - PowerShell Activity` |

### Panel 3.3 — New user accounts

| Setting | Value |
|---|---|
| Type | **Data table** |
| Query | `data.win.system.eventID: ("4720" or "4722" or "4726" or "4732")` |
| Buckets | Terms → `data.win.eventdata.targetUserName`; Terms → `data.win.eventdata.subjectUserName`; Terms → `data.win.system.eventID` |
| Save as | `SO - Account Management` |

### Panel 3.4 — Suspicious processes

| Setting | Value |
|---|---|
| Type | **Data table** |
| Query | `rule.id: (100130 or 100131 or 100132 or 100133 or 100134)` |
| Buckets | Terms → `data.win.eventdata.image` → Size 10; Terms → `data.win.eventdata.parentImage` → Size 5 |
| Save as | `SO - Suspicious Processes` |

### Panel 3.5 — Top parent → child pairs

| Setting | Value |
|---|---|
| Type | **Data table** |
| Query | `data.win.system.eventID: "1"` |
| Buckets | Terms → `data.win.eventdata.parentImage` → Size 10; Terms → `data.win.eventdata.image` → Size 5 |
| Save as | `SO - Process Ancestry` |

> This single table is the most useful hunting panel in the lab: unusual parent→child pairs
> (`winword.exe → powershell.exe`) stand out immediately against the normal baseline.

Assemble as dashboard `SentinelOps - Endpoint Activity`.

---

## Dashboard 4 — Timeline

**Purpose:** answers "when did this happen, and what else happened around it?"

### Panel 4.1 — Alerts over time by severity

| Setting | Value |
|---|---|
| Type | **Vertical bar** (stacked) |
| Y-axis | Count |
| X-axis | Date histogram → `timestamp` → interval Auto |
| Split series | Terms → `rule.level` → Size 10 |
| Options | Mode: **stacked** |
| Save as | `SO - Alert Timeline` |

### Panel 4.2 — Alert stream (saved search)

Build in *Discover*, not *Visualize*:

1. ☰ → **Discover**, index pattern `wazuh-alerts-*`.
2. Query: `rule.level >= 8`.
3. Add these columns from the left field list, in order:
   `timestamp`, `agent.name`, `rule.level`, `rule.description`,
   `data.win.eventdata.targetUserName`, `data.win.eventdata.ipAddress`.
4. Sort by `timestamp` descending.
5. **Save** as `SO - Medium and above alerts`, then add it to a dashboard with
   *Add from library*.

Saved searches are what an analyst actually works from during an investigation — build at
least these three:

| Saved search | Query |
|---|---|
| `SO - Medium and above alerts` | `rule.level >= 8` |
| `SO - Authentication events` | `data.win.system.eventID: ("4624" or "4625" or "4740")` |
| `SO - Process creation` | `data.win.system.eventID: "1"` |

---

## Dashboard 5 — MITRE ATT&CK

**Purpose:** answers "which adversary techniques am I actually seeing, and where are my gaps?"

Wazuh ships a **built-in MITRE ATT&CK module**: ☰ → *MITRE ATT&CK* → *Framework / Intelligence*.
Use it first — it renders the matrix with detected techniques highlighted. Then build these two
panels for your own dashboard:

### Panel 5.1 — Techniques by frequency

| Setting | Value |
|---|---|
| Type | **Horizontal bar** |
| Query | `rule.mitre.id: *` |
| Y-axis | Count |
| X-axis | Terms → `rule.mitre.id` → Size 15 → Order by Count descending |
| Save as | `SO - MITRE Techniques` |

### Panel 5.2 — Tactics coverage

| Setting | Value |
|---|---|
| Type | **Pie** |
| Query | `rule.mitre.tactic: *` |
| Bucket | Terms → `rule.mitre.tactic` → Size 12 |
| Save as | `SO - MITRE Tactics` |

### Panel 5.3 — Technique detail table

| Setting | Value |
|---|---|
| Type | **Data table** |
| Buckets | Terms → `rule.mitre.id` → Size 20; Terms → `rule.mitre.technique` → Size 1; Terms → `agent.name` → Size 5 |
| Save as | `SO - MITRE Detail` |

Assemble as dashboard `SentinelOps - MITRE ATT&CK`.

---

## Assembling and sharing

1. ☰ → **Dashboards** → *Create dashboard*.
2. *Add from library* → add the saved visualisations for that dashboard.
3. Drag to arrange: **metrics across the top**, tables and charts below, timeline at the bottom.
4. Set the time picker to *Last 24 hours* and enable auto-refresh (30 s) for the overview.
5. **Save** with "Store time with dashboard" **unchecked**, so the dashboard always opens on the
   analyst's chosen range.

**Suggested layout for `SentinelOps - SOC Overview`:**

```
+------------+------------+------------+------------+------------+
|  Total     |  Critical  |   High     |  Medium    |    Low     |   <- Metric row
+------------+------------+------------+------------+------------+
|      Alert Timeline (stacked by severity)                      |
+---------------------------+------------------------------------+
|   Top 10 Rules Fired      |   MITRE Techniques by frequency     |
+---------------------------+------------------------------------+
|   Top Source IPs          |   Targeted Accounts                 |
+---------------------------+------------------------------------+
|      SO - Medium and above alerts (saved search)                |
+----------------------------------------------------------------+
```

**Export for backup / version control (optional):**
☰ → *Dashboards Management* → *Saved objects* → select your objects → **Export** → save the
`.ndjson` next to this file. Check the export before committing it — saved objects can contain
host names and IP addresses.

---

## Analyst tips

| Tip | Why |
|---|---|
| Always check the **time picker** before concluding "there is no data" | The single most common dashboard mistake |
| Use `rule.level >= 8` as your working filter | Filters out informational noise without hiding it |
| Click a value in a table → **+** to filter, **−** to exclude | Fastest pivot in the interface |
| Pin a filter (the pin icon) | The filter survives when you move between Discover and dashboards |
| Open the raw JSON of an alert (expand the row → *JSON* tab) | The alert card hides fields you will need |
| Keep everything in **UTC** | Incident timelines break silently across mixed time zones |
