# Detection Engineering Methodology

How every detection in SentinelOps was designed, written, tested, tuned and documented.
This is the process, not the rules — the rules live in
[`/detection-rules`](../detection-rules).

---

## 1. The detection lifecycle used in this lab

```
   1. Threat selection        What behaviour matters, and to whom?
            |
   2. Data source validation  Do I actually have the telemetry to see it?
            |
   3. Baselining              What does normal look like on this endpoint?
            |
   4. Rule authoring          Detect the behaviour, not one specific tool
            |
   5. Unit testing            wazuh-logtest with a real captured event
            |
   6. Simulation testing      Run the safe lab scenario end to end
            |
   7. Tuning                  Remove FPs narrowly, never by deleting the logic
            |
   8. Documentation           Severity, MITRE, FPs, investigation, response
            |
   9. Review                  Re-test after every Wazuh or Sysmon change
```

A detection that is not documented is not finished: the analyst receiving the alert at 03:00
needs to know what it means, how to investigate it, and what to do — otherwise the alert will
be closed as "noise" and the detection is worthless.

---

## 2. Step 1 — Threat selection

Detections were selected against three criteria:

| Criterion | Question |
|---|---|
| **Relevance** | Does this actually happen to small organisations? (brute force, phishing → PowerShell, backdoor accounts: yes) |
| **Observability** | Can a single Windows endpoint with Sysmon see it? (LSASS access: yes. Firewall evasion: no) |
| **Actionability** | Can an L1 analyst do something concrete when it fires? |

Deliberately **excluded**: anything requiring Active Directory, network sensors, email
gateways or EDR APIs — the lab cannot observe them, and claiming detections you cannot test is
dishonest.

---

## 3. Step 2 — Data source validation

Before writing a single rule, prove the telemetry exists. For every detection:

```powershell
# 1. Does Windows produce the event at all?
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 1

# 2. Does the agent collect that channel?
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern "localfile" -Context 0,3
```

```bash
# 3. Does the event reach the manager?
sudo tail -f /var/ossec/logs/archives/archives.json | grep 4625

# 4. What are the EXACT field names after decoding?
sudo tail -1 /var/ossec/logs/archives/archives.json | python3 -m json.tool
```

Step 4 is the one beginners skip, and it is the reason most first custom rules never fire.
Wazuh lowercases the first letter of every Windows `EventData` field:

| Windows XML | Wazuh field |
|---|---|
| `TargetUserName` | `win.eventdata.targetUserName` |
| `IpAddress` | `win.eventdata.ipAddress` |
| `ParentImage` | `win.eventdata.parentImage` |
| `ScriptBlockText` | `win.eventdata.scriptBlockText` |

**Never guess a field name. Read it from a real event.**

---

## 4. Step 3 — Baselining

Run the lab for at least 24–48 hours of *normal* use (browse, install something, log in and
out, reboot) with **no** simulation, then measure:

```bash
# Top rules by volume
sudo grep -o '"id":"[0-9]*"' /var/ossec/logs/alerts/alerts.json | sort | uniq -c | sort -rn | head -20

# Alert levels distribution
sudo python3 - <<'PY'
import json, collections
c = collections.Counter()
for line in open('/var/ossec/logs/alerts/alerts.json'):
    try: c[json.loads(line)['rule']['level']] += 1
    except Exception: pass
for lvl, n in sorted(c.items()): print(f"level {lvl:>2}: {n}")
PY
```

```powershell
# Sysmon event distribution on the endpoint
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20000 |
    Group-Object Id | Sort-Object Count -Descending | Format-Table Count, Name
```

**Baseline findings — NOT YET MEASURED.** The lab has not been built or run, so the table
below is a **worked example** of the reasoning, not data collected from a real baseline. The
"Value" column shows illustrative figures used to derive the current thresholds; the
"Measured value" column must be filled in from your own 48-hour baseline before the thresholds
are trusted. Where your measurement differs, retune the rule.

| Observation | Illustrative value (assumed) | Measured value | Consequence for the rules |
|---|---|---|---|
| Highest legitimate failed-logon burst | e.g. 3 in 2 minutes (expired password) | `<NOT YET MEASURED>` | Brute-force threshold currently **8 in 120 s** |
| Discovery commands run by the user/OS per hour | e.g. 0–2, rarely >2 distinct binaries/minute | `<NOT YET MEASURED>` | Recon burst threshold currently **5 distinct in 60 s** |
| Encoded PowerShell from legitimate software | assumed 0 | `<NOT YET MEASURED>` | Suspicious-switch rule currently has no exclusions |
| Local accounts created | assumed 0 | `<NOT YET MEASURED>` | Every 4720 alerts (level 8) |
| 4672 events per day | assumed tens (SYSTEM/service logons) | `<NOT YET MEASURED>` | Service accounts excluded, dropped to level 5 |

**Thresholds must come from measurement, not from a blog post — and not from this table.**
The figures above are assumptions used to author the first draft of the rules; copying a number
without baselining your own environment is how a SOC ends up with an alert queue nobody reads.

---

## 5. Step 4 — Rule authoring principles

### 5.1 Detect the behaviour, not the tool

| Weak rule | Why it fails | Stronger rule |
|---|---|---|
| `commandLine contains "mimikatz"` | Rename the file and it is gone | Handle opened against `lsass.exe` with suspicious access mask (`100153`) |
| `image ends with "nc.exe"` | Any binary can be renamed | Interpreter or LOLBin making an outbound connection (`100114`) |
| `commandLine contains "Invoke-Mimikatz"` | Trivial string change | Script block containing an in-memory execution cradle (`100113`) |

### 5.2 Chain on stable identifiers

Every rule in this lab uses `<if_group>` rather than `<if_sid>`:

```xml
<if_group>windows</if_group>       <!-- stable across Wazuh releases -->
<if_group>sysmon_event1</if_group> <!-- stable group name for Sysmon EID 1 -->
```

Reason: Wazuh matches **one rule per level** and loads the built-in ruleset first, so a custom
rule written as a *sibling* of a built-in rule usually never fires. Making it a **child** of
whatever already matched is the reliable pattern — and built-in rule *IDs* change between
releases while group names do not.

### 5.3 Write precise regex

| Practice | Example | Why |
|---|---|---|
| Anchor exact values | `^4625$` | `4625` alone also matches `14625` |
| Case-insensitive | `(?i)-encodedcommand` | Attackers vary case deliberately |
| Escape path separators | `\\powershell\.exe` | `.` is a regex wildcard; leading `\\` prevents `notpowershell.exe` |
| Bound wildcards | `.{0,80}` not `.*` | Unbounded matches are slow and over-match |
| Pair binary **and** argument | `certutil` **and** `-urlcache` | `certutil` alone has legitimate uses |

### 5.4 Use correlation deliberately

| Element | Meaning | Used in |
|---|---|---|
| `frequency` + `timeframe` | N matches within T seconds | `100101`, `100104`, `100131` |
| `same_field` | All N matches share a field value (one source IP, one host) | `100101`, `100131` |
| `different_field` | The N matches must differ in a field (many usernames, many binaries) | `100104`, `100131` |
| `if_matched_sid` | A different rule fired recently — cross-event-type correlation | `100102`, `100121` |

`same_field` is what stops "four failures from a confused user + four from an attacker" being
merged into one misleading alert.

### 5.5 Assign severity honestly

| Level | Meaning | Test to apply |
|---|---|---|
| 0–3 | Informational | "Would I want a ticket for this?" No. |
| 4–7 | Low | "Review this shift." |
| 8–11 | Medium | "Someone must look within an hour." |
| 12–14 | High | "Stop what you are doing." |
| 15 | Critical | "Confirmed compromise." |

Inflating severity is worse than under-alerting: an analyst who sees ten level-12 alerts a day
that are all benign will stop reading level 12.

### 5.6 Make the description self-sufficient

```xml
<description>SentinelOps: Possible brute force - 8 or more failed logons from $(win.eventdata.ipAddress) within 120 seconds</description>
```

The analyst should be able to start triage from the alert list alone. `$(field)` interpolation
puts the who/where/what in the title.

### 5.7 Always attach MITRE

```xml
<mitre><id>T1110.001</id></mitre>
```

Only use IDs you have verified on `attack.mitre.org`. An invented technique ID makes every
other claim in a portfolio suspect — and Wazuh will log an error if the ID is not in its
bundled ATT&CK database.

---

## 6. Step 5 — Unit testing with `wazuh-logtest`

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste one complete JSON event captured from `/var/ossec/logs/archives/archives.json`. Read the
output:

```
**Phase 1: Completed pre-decoding.
**Phase 2: Completed decoding.
        name: 'windows_eventchannel'
        win.system.eventID: '4625'
        win.eventdata.targetUserName: 'svc-backup'
        win.eventdata.ipAddress: '192.168.56.30'
**Phase 3: Completed filtering (rules).
        id: '100100'
        level: '3'
        description: 'SentinelOps: Windows failed logon for user svc-backup ...'
        mitre.id: '["T1110"]'
```

| Symptom | Diagnosis |
|---|---|
| Phase 2 shows no fields | Decoder did not parse — wrong log format or malformed JSON |
| Phase 3 shows a built-in rule ID, not yours | Your rule is not a child of the matched rule, or a field regex fails |
| Phase 3 shows nothing | No rule matched at all |
| `mitre.id` missing | The technique ID is not in this build's ATT&CK database |

Syntax-check without restarting the manager:

```bash
sudo /var/ossec/bin/wazuh-logtest -t
```

Test a correlation rule by replaying the same event repeatedly — `wazuh-logtest` maintains
state within a session, so pasting the event 8 times should produce `100101` on the trigger.

---

## 7. Step 6 — Simulation testing

Unit tests prove the rule parses. Simulation proves the **whole chain** works: audit policy →
event → agent → decoder → rule → correlation → index → dashboard.

| Detection | Script | Expected alerts |
|---|---|---|
| SO-DET-001 | `Invoke-LabFailedLogons.ps1 -Attempts 12` | `100100` ×12, `100101` |
| SO-DET-002 | `Invoke-LabPowerShellActivity.ps1 -Scenario All` | `100110`, `100111`, `100113` |
| SO-DET-003 | `New-LabTestAccount.ps1 -AddToAdministrators` | `100120`, `100140`, `100121` |
| SO-DET-004 | `Invoke-LabSuspiciousProcess.ps1 -Scenario Recon` | `100130` ×n, `100131` |
| SO-DET-005 | `Invoke-LabPrivilegeActivity.ps1` | `100140`, `100143`/`100144`, `100141` |

Record for every test: timestamp, expected rule, actual rule, time-to-alert, screenshot. That
record is what turns "I wrote some rules" into "I validated my detections".

---

## 8. Step 7 — Tuning

**Rule for tuning: narrow the exclusion to the exact known-good thing, never to the category.**

| Bad exclusion | Why it is dangerous | Good exclusion |
|---|---|---|
| Ignore all PowerShell from Administrators | Attackers operate as admin | Ignore the specific management-agent parent image + script path |
| Ignore `image contains chrome` | `chrome_update.exe` in `%TEMP%` now invisible | Ignore the full signed path `C:\Program Files\Google\Chrome\Application\chrome.exe` |
| Ignore all 4625 from `10.0.0.0/8` | Blinds you to internal attackers | Ignore the specific scanner IP, documented and time-limited |

Implement exclusions as a **child rule at level 0**, which suppresses the alert while leaving
the parent detection intact:

```xml
<rule id="100190" level="0">
  <if_sid>100111</if_sid>
  <field name="win.eventdata.parentImage">(?i)C:\\Program Files\\Corp\\ManagementAgent\\agent\.exe</field>
  <description>Tuned out: encoded PowerShell launched by the approved management agent (ticket CHG-1042)</description>
</rule>
```

Every tuning decision gets: **what** was excluded, **why**, **who approved it**, and a **review
date**. Undocumented tuning is how detections silently die.

---

## 9. Step 8 — Documentation template

Every detection in this repository documents the same nine items:

1. Detection name and ID
2. Description — what behaviour, why it matters
3. Data source and event IDs (Windows + Sysmon)
4. The Wazuh rule, **explained line by line**
5. Severity and the reasoning behind the level
6. MITRE ATT&CK tactic + technique (verified)
7. Known false positives and how to recognise them
8. Investigation steps, with the actual queries to run
9. Recommended response by verdict

---

## 10. Step 9 — Review triggers

Re-test detections after **any** of the following:

* a Wazuh manager or agent upgrade (rule IDs and decoders can change);
* a Sysmon version or config change;
* a Windows feature update (channel names and event schemas change);
* an alert volume shift of more than ~30 % week over week;
* any false negative found during an investigation — the most valuable review trigger there is.

---

## 11. Known limitations of these detections (stated honestly)

| Limitation | Impact | Mitigation |
|---|---|---|
| Thresholds are tuned to a single idle workstation | Will produce false positives on a busy or shared host | Re-baseline before reuse |
| No Active Directory | Domain techniques (Kerberoasting, DCSync, golden ticket) are not covered | Out of scope; listed as a future improvement |
| Rules rely on Sysmon being healthy | An attacker with SYSTEM can stop Sysmon | Rule `100152` alerts on Sysmon service/config change; agent-side 4688 is the fallback |
| Regex-based command-line matching can be evaded | Heavy obfuscation may bypass `100111` | Rule `100113` on **decoded** script blocks is the compensating control |
| Correlation windows are fixed | A slow attacker (1 attempt/minute) evades the 120 s window | A longer, lower-severity companion rule would be the next iteration |

Naming your own blind spots is a detection-engineering skill in itself, and it is what an
interviewer is listening for.
