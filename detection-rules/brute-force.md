# Detection 01 — Brute Force / Failed Authentication

> Laboratory detection. All data shown was generated inside the isolated SentinelOps lab.

| Field | Value |
|---|---|
| **Detection name** | Windows Brute Force Authentication Attempt |
| **Detection ID** | SO-DET-001 |
| **Wazuh rules** | `100100`, `100101`, `100102`, `100103`, `100104` |
| **Data source** | Windows Security event log (endpoint), collected by the Wazuh agent |
| **Windows Event IDs** | `4625` (failed logon), `4624` (successful logon), `4740` (account lockout), `4776` (NTLM credential validation) |
| **Sysmon Event ID** | Not applicable — authentication is not a Sysmon event |
| **Severity** | Low (single failure) → **Medium 10** (burst) → **High 12** (burst followed by success) |
| **MITRE ATT&CK** | **TA0006 Credential Access** — [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force, [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing, [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Password Spraying |

---

## 1. Description

An attacker who has a valid username but no password will try passwords repeatedly until one
works (**password guessing**), or try one common password against many usernames to avoid
lockout (**password spraying**). Both produce the same primitive artefact on Windows: a burst
of **Event ID 4625 — An account failed to log on**.

A single 4625 is meaningless: users mistype passwords every day. The *detection* is in the
**rate, the spread and the outcome**:

| Shape | Meaning | Rule |
|---|---|---|
| Many failures, **one** account, **one** source | Password guessing | `100101` |
| Many failures, **many** accounts, **one** source | Password spraying | `100104` |
| Many failures **then a success** from the same source | Possible compromise | `100102` |
| Failures reach the lockout threshold | Denial of service or noisy attacker | `100103` |

---

## 2. Key fields in Event ID 4625

| Field | Wazuh field name | Why the analyst needs it |
|---|---|---|
| Target account | `win.eventdata.targetUserName` | Who is being attacked |
| Source network address | `win.eventdata.ipAddress` | Where it is coming from |
| Source port | `win.eventdata.ipPort` | Distinguishes separate connections |
| Workstation name | `win.eventdata.workstationName` | Attacker-controlled, but useful as an IOC |
| Logon type | `win.eventdata.logonType` | How they are connecting |
| Failure reason | `win.eventdata.status` / `subStatus` | Bad password vs. non-existent user |
| Caller process | `win.eventdata.processName` | Which service handled the attempt |
| Host | `win.system.computer` | Target machine |
| Time | `win.system.systemTime` | Timeline |

### Logon types worth memorising

| Type | Meaning | Typical brute force source |
|---|---|---|
| 2 | Interactive (console / keyboard) | Physical access |
| **3** | **Network (SMB, file share, remote authentication)** | **Most common in this lab** |
| 4 | Batch (scheduled task) | Stale saved credentials |
| 5 | Service | Service account with a rotated password |
| 7 | Unlock (workstation unlock) | Physical access |
| **10** | **RemoteInteractive (RDP)** | **Internet-exposed RDP** |
| 11 | CachedInteractive | Laptop offline logon |

### Failure sub-status codes (the most useful triage field in 4625)

| `subStatus` | Meaning | What it tells you |
|---|---|---|
| `0xC0000064` | User name does not exist | **Enumeration** — attacker is guessing usernames |
| `0xC000006A` | Wrong password | **Password guessing** — the username is valid |
| `0xC0000234` | Account locked out | Threshold reached |
| `0xC0000072` | Account disabled | Attacker is using stale knowledge |
| `0xC0000070` | Workstation restriction | Policy blocked the logon |
| `0xC000015B` | Logon type not granted | User exists but may not log on this way |
| `0xC0000193` | Account expired | Stale account |

> **Triage shortcut:** a mix of `0xC0000064` (unknown user) means enumeration/spraying.
> All `0xC000006A` (wrong password) against one account means targeted guessing — the
> username is real, which is worse.

---

## 3. Wazuh rules, explained line by line

```xml
<rule id="100100" level="3">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4625$</field>
  <description>SentinelOps: Windows failed logon for user $(win.eventdata.targetUserName) from $(win.eventdata.ipAddress) [logon type $(win.eventdata.logonType)]</description>
  <mitre><id>T1110</id></mitre>
</rule>
```

* `<if_group>windows</if_group>` — makes this a **child** of whatever built-in Windows rule
  already matched the event. Wazuh only matches one rule per level, and the built-in ruleset
  loads first, so a sibling rule would never fire. Chaining on the group is also upgrade-safe:
  built-in rule *IDs* change between releases, group names do not.
* `<field name="win.system.eventID">^4625$</field>` — anchored regex. Without `^` and `$`,
  `4625` would also match a hypothetical `14625`.
* **Level 3 is deliberate.** One failed logon is not an incident. This rule exists to normalise
  the fields that the correlation rules consume, and to give hunters a clean search term.
* `$(field)` in the description puts the username and source IP directly in the alert title, so
  the analyst can triage from the alert list without opening the raw event.

```xml
<rule id="100101" level="10" frequency="8" timeframe="120">
  <if_matched_sid>100100</if_matched_sid>
  <same_field>win.eventdata.ipAddress</same_field>
  <description>SentinelOps: Possible brute force ...</description>
  <mitre><id>T1110.001</id></mitre>
</rule>
```

* `frequency="8" timeframe="120"` — the correlation window: eight matches of rule `100100`
  within 120 seconds.
* `<same_field>win.eventdata.ipAddress</same_field>` — **the critical line**. Without it, four
  failures from a forgetful user plus four from an attacker would be merged into one false
  alert. With it, the eight failures must come from the *same* source.
* **Why 8 / 120 s?** Measured against the lab baseline: over a week of normal use the highest
  legitimate burst was 3 failures in 2 minutes (a user with an expired password). Eight gives
  clear separation while still catching a slow attacker. Document your own baseline before
  copying this number.

```xml
<rule id="100102" level="12" timeframe="600">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4624$</field>
  <if_matched_sid>100101</if_matched_sid>
  <same_field>win.eventdata.ipAddress</same_field>
</rule>
```

* This is the alert that changes the shift. A **successful** logon (4624) from an IP that
  triggered the brute-force rule within the last 10 minutes means the guessing may have
  succeeded. Level 12 = High, triage immediately.

```xml
<rule id="100104" level="12" frequency="10" timeframe="300">
  <if_matched_sid>100100</if_matched_sid>
  <same_field>win.eventdata.ipAddress</same_field>
  <different_field>win.eventdata.targetUserName</different_field>
</rule>
```

* `<different_field>` inverts the logic: same source, **different** usernames = password
  spraying (T1110.003). Spraying deliberately stays under the lockout threshold per account,
  so rule `100101` alone would miss it.

> **Verification before you trust these rules**
> ```bash
> sudo /var/ossec/bin/wazuh-logtest      # paste a real 4625 JSON event, confirm rule 100100 fires
> sudo /var/ossec/bin/wazuh-logtest -v   # verbose: shows the full rule chain that matched
> ```
> Confirm the exact number of events needed to trip `frequency` on your version — Wazuh counts
> matches after the first one in some releases. Adjust the threshold to what you measure.

---

## 4. Generating the telemetry in the lab (MANUAL STEP)

Use [`/scripts/Invoke-LabFailedLogons.ps1`](../scripts/Invoke-LabFailedLogons.ps1).

```powershell
# Run on LAB-ATTACK01 (192.168.56.30) so the alert carries a remote source IP.
# LAB ONLY. Target must be your own lab VM.
.\Invoke-LabFailedLogons.ps1 -TargetHost 192.168.56.20 -UserName svc-backup -Attempts 12 -DelaySeconds 3
```

Prerequisite: **Audit Logon** must be enabled for Failure (see
[`/documentation/installation.md`](../documentation/installation.md) §6).

---

## 5. False positives

| Cause | How to recognise it | Handling |
|---|---|---|
| User changed their password and a mapped drive / Outlook profile keeps retrying the old one | Same account, logon type 3, source is the user's own workstation, failures repeat on a fixed interval for hours | Tune: exclude the source host after confirming with the user; ask them to reboot / clear credential manager |
| Service account with a rotated password | `targetUserName` starts with `svc-`, logon type 5 (Service) or 4 (Batch), source is the local host | Raise a change ticket, not an incident |
| Scheduled task holding stale credentials | Logon type 4, regular interval matching the task schedule | Identify the task with `schtasks /query /v` |
| Vulnerability scanner or monitoring tool | Source IP belongs to the known scanner, many hosts affected simultaneously | Add the scanner IP to a documented allowlist |
| User locked out after a holiday | 3–5 failures then success, single source, business hours | Close as benign |

**A false positive is not "an alert I do not like" — it is an alert where the rule logic fired
correctly but the activity is legitimate.** Every FP closed in this lab is recorded with its
tuning decision, so the rule improves instead of being ignored.

---

## 6. Investigation steps (SOC L1)

1. **Scope the burst.** In *Threat Hunting → Discover*, filter
   `rule.id:100101 or rule.id:100100` for the last 24 h. Record: how many failures, over what
   period, from which source IP(s), against which account(s).
2. **Classify the source IP.** Internal lab host, another endpoint, or unexpected?
   Note the logon type — type 3 (SMB) and type 10 (RDP) mean remote network access.
3. **Read the sub-status.** `0xC000006A` (valid user, wrong password) is more serious than
   `0xC0000064` (user does not exist).
4. **Check for success.** This is the decisive question. Search:
   `data.win.system.eventID:4624 AND data.win.eventdata.ipAddress:"<source IP>"`
   for the window covering the failures and the 30 minutes after.
5. **If a success exists**, pivot to that logon session: take the `logonId` and search for
   process creation (Sysmon EID 1 / Security 4688) carrying the same `logonId`. Ask: did the
   session do anything?
6. **Check for follow-on activity** on the target host: new accounts (4720), group changes
   (4732), scheduled tasks (4698), services (7045), PowerShell (4104).
7. **Check the account.** Is it enabled, privileged, service or human? `net user <name>`.
8. **Check for lockout** (4740) — evidence the threshold was reached.
9. **Decide.** No success and a known source → tune or close. No success, unknown source →
   Low/Medium incident, block the source. Success → **escalate immediately** as a suspected
   account compromise.

**Wazuh Discover queries used**

```
rule.id:(100100 OR 100101 OR 100102 OR 100104)
data.win.system.eventID:4625 AND data.win.eventdata.targetUserName:"svc-backup"
data.win.eventdata.ipAddress:"192.168.56.30"
data.win.system.eventID:4624 AND data.win.eventdata.logonType:"3"
agent.name:"WIN-SOC-EP01" AND rule.groups:"authentication_failed"
```

---

## 7. Recommended response

| Verdict | Action |
|---|---|
| **False positive** | Document the cause, tune the rule (exclude the specific source/account), close. |
| **True positive, no success** | Block the source IP at the host firewall, confirm the account's password meets policy, verify lockout policy is enabled, monitor for 24 h, close as *Contained*. |
| **True positive, successful logon** | **Escalate to L2/IR.** Disable the account (`Disable-LocalUser`), force a password reset, isolate the host from the network, preserve the Security and Sysmon logs, begin a full compromise assessment of everything that session touched. |

**Hardening recommendations produced by this detection**

* Account lockout policy: 5 attempts / 15-minute window / 15-minute duration.
* Do not expose RDP; if it is required, restrict it by source IP and require NLA + MFA.
* Rename or disable the built-in Administrator account and disable unused local accounts.
* Enforce a password policy strong enough that 12 guesses cannot succeed.
