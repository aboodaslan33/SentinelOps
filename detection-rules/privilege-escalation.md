# Detection 05 — Privilege Escalation and Administrative Activity

> Laboratory detection. Every action described was performed by the lab owner on their own
> isolated virtual machine. This document describes **how to detect** privilege changes; it is
> not a guide to compromising any system.

| Field | Value |
|---|---|
| **Detection name** | Privilege Escalation / Unexpected Administrative Activity |
| **Detection ID** | SO-DET-005 |
| **Wazuh rules** | `100140`, `100141`, `100142`, `100143`, `100144`, `100145`, `100151` |
| **Data source** | Windows Security log, Windows System log, Sysmon Operational log |
| **Windows Event IDs** | `4732` (member added to local group), `4728` (global group), `4672` (special privileges assigned to new logon), `4673`/`4674` (privileged service/object operation), `4698` (scheduled task created), `4697` (service installed, Security log), `7045` (service installed, System log), `4719` (audit policy changed), `4624` type 10 (RDP logon) |
| **Sysmon Event IDs** | `1` (process creation — `schtasks.exe`, `sc.exe`, `net localgroup`, UAC-bypass parents), `13` (registry value set — auto-elevation hijack keys) |
| **Severity** | Low 5 (privileged logon context) → **Medium 10** (scheduled task / service created) → **High 12–13** (privileged group change, UAC bypass pattern) |
| **MITRE ATT&CK** | **TA0004 Privilege Escalation** — [T1548.002](https://attack.mitre.org/techniques/T1548/002/) Abuse Elevation Control Mechanism: Bypass User Account Control, [T1098.007](https://attack.mitre.org/techniques/T1098/007/) Additional Local or Domain Groups, [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task, [T1543.003](https://attack.mitre.org/techniques/T1543/003/) Windows Service, [T1078.003](https://attack.mitre.org/techniques/T1078/003/) Valid Accounts: Local Accounts; **TA0005** — [T1562.002](https://attack.mitre.org/techniques/T1562/002/) Disable Windows Event Logging |

---

## 1. Description

Privilege escalation is the step between "I can run code as a user" and "I own this machine".
On a Windows workstation the observable outcomes are limited and well understood, which makes
this one of the most detectable stages of an intrusion:

| Outcome the attacker wants | Windows artefact | Rule |
|---|---|---|
| Put an account into `Administrators` | `4732` + Sysmon `net localgroup administrators /add` | `100140`, `100121` |
| Run code as SYSTEM on a schedule | `4698`, Sysmon `schtasks.exe /create /ru SYSTEM` | `100143`, `100144` |
| Run code as SYSTEM as a service | `7045` / `4697`, Sysmon `sc.exe create` | `100145` |
| Get a High-integrity process without a UAC prompt | Child process under an auto-elevating binary (`fodhelper.exe`, `computerdefaults.exe`, `sdclt.exe`, `eventvwr.exe`, `slui.exe`), registry write to the associated hijack key | `100142` |
| Use an account that already has privileges | `4672` on a non-service account, `4624` type 10 | `100141` |
| Stop the evidence being recorded | `4719`, `1102`, Sysmon service stopped | `100151`, `100150`, `100152` |

**Safe lab equivalent used in this project:** the scenario in `/incidents/incident-005-privilege-escalation.md`
is produced by *administrative actions performed deliberately by the lab owner* — adding a lab
account to the local Administrators group, creating a scheduled task that runs as SYSTEM, and
starting an elevated process. These generate exactly the same telemetry an attacker would
generate, with no exploit, no vulnerability and no third-party tooling involved.

---

## 2. Key fields

| Event | Field | Wazuh field name | Meaning |
|---|---|---|---|
| 4732 | Group | `win.eventdata.targetUserName` | The group that changed (**not** the member) |
| 4732 | Member | `win.eventdata.memberName` / `memberSid` | The account that was added |
| 4732 | Actor | `win.eventdata.subjectUserName` | Who made the change |
| 4672 | Account | `win.eventdata.subjectUserName` | Which logon received admin privileges |
| 4672 | Privileges | `win.eventdata.privilegeList` | Which privileges (see table below) |
| 4698 | Task name | `win.eventdata.taskName` | The scheduled task |
| 4698 | Task XML | `win.eventdata.taskContent` | **Contains the command that will run and the principal (e.g. SYSTEM)** |
| 7045 | Service | `win.eventdata.serviceName`, `imagePath`, `serviceType`, `startType` | What will run, from where, as whom |
| Sysmon 1 | Integrity | `win.eventdata.integrityLevel` | `Medium` = normal user, `High`/`System` = elevated |
| Sysmon 1 | Logon ID | `win.eventdata.logonId` | Joins the process back to its 4624 session |

### Privileges in 4672 worth recognising

| Privilege | Why an attacker wants it |
|---|---|
| `SeDebugPrivilege` | Open any process — the prerequisite for credential dumping from LSASS |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Read or write any file regardless of ACLs (SAM, SYSTEM hives) |
| `SeTakeOwnershipPrivilege` | Seize ownership of protected objects |
| `SeImpersonatePrivilege` | Token impersonation — the basis of many service-account escalations |
| `SeLoadDriverPrivilege` | Load a kernel driver |
| `SeTcbPrivilege` | Act as part of the operating system |

`4672` fires for every administrative logon including `SYSTEM`, which is why rule `100141`
excludes the built-in service accounts and stays at level 5: it is **context for an
investigation, not an alert to chase**.

---

## 3. Wazuh rules, explained

```xml
<rule id="100140" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4732$</field>
  <field name="win.eventdata.targetUserName">(?i)^Administrators$|^Remote Desktop Users$|^Backup Operators$|^Power Users$</field>
  <mitre><id>T1098.007</id></mitre>
</rule>
```

* Scoped to the four local groups that actually grant power. Anchoring with `^...$` prevents an
  unrelated group such as `Helpdesk-Administrators-ReadOnly` from triggering it.
* Level 12 (High) because on a single-user workstation this should essentially never happen
  outside a change window.

```xml
<rule id="100141" level="5">
  <field name="win.system.eventID">^4672$</field>
  <field name="win.eventdata.subjectUserName" negate="yes">(?i)^SYSTEM$|^LOCAL SERVICE$|^NETWORK SERVICE$|\$$</field>
  <mitre><id>T1078.003</id></mitre>
</rule>
```

* `negate="yes"` removes the built-in service accounts. `\$$` additionally removes **computer
  accounts**, which always end in `$` (e.g. `WIN-SOC-EP01$`) — a detail that catches out a lot
  of first-time rule writers.
* Kept at Low deliberately: this event is high volume and its value is as **supporting
  evidence** in a timeline ("the session that created the account held SeDebugPrivilege").

```xml
<rule id="100142" level="13">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.parentImage">(?i)\\fodhelper\.exe|\\computerdefaults\.exe|\\sdclt\.exe|\\eventvwr\.exe|\\slui\.exe</field>
  <mitre><id>T1548.002</id></mitre>
</rule>
```

* These five Microsoft binaries **auto-elevate without a UAC prompt** by design. Publicly
  documented UAC-bypass techniques hijack the registry entry each one consults so that it
  launches an attacker-chosen process at High integrity instead.
* The detection is deliberately on the **parent relationship**, not on the registry key: it is
  agnostic to which specific variant is used, because any of them must ultimately spawn a child
  under one of these binaries.
* A complementary detection is Sysmon EID 13 writes to
  `HKCU\Software\Classes\ms-settings\shell\open\command` and `...\Folder\shell\open\command`,
  which the Sysmon config in this repo already collects.

```xml
<rule id="100143" level="10">   <!-- Security 4698: scheduled task created -->
<rule id="100144" level="12">   <!-- Sysmon: schtasks.exe /create -->
<rule id="100145" level="10">   <!-- System 7045 / Security 4697: service installed -->
```

* Two angles on the same techniques — the **audit** angle (4698/7045, authoritative, includes
  the task XML and service image path) and the **process** angle (Sysmon, includes the parent
  and the user who ran it). Having both means a detection survives one source being disabled,
  and gives the analyst both "what was configured" and "who configured it".

```xml
<rule id="100151" level="12">
  <field name="win.system.eventID">^4719$</field>
  <mitre><id>T1562.002</id></mitre>
</rule>
```

* Audit policy changes are the quiet version of clearing the log: instead of deleting evidence,
  the attacker stops it being created. There is no routine reason for this on a monitored
  endpoint outside a documented change.

---

## 4. Generating the telemetry in the lab (MANUAL STEP)

Use [`/scripts/Invoke-LabPrivilegeActivity.ps1`](../scripts/Invoke-LabPrivilegeActivity.ps1).
It performs three **ordinary administrative actions** and then reverses all of them:

1. adds a lab account to `Administrators` (→ 4732, 100140)
2. creates a scheduled task that runs `cmd.exe /c echo` as SYSTEM (→ 4698, 100143/100144)
3. starts an elevated process to produce a privileged logon (→ 4672, 100141)

No exploit, no vulnerability, no third-party tool. Run it as Administrator on `WIN-SOC-EP01`.

```powershell
.\Invoke-LabPrivilegeActivity.ps1 -AccountName lab-svc-update -CleanUp
```

---

## 5. False positives

| Cause | Recognition | Handling |
|---|---|---|
| IT adding a user to Administrators for a support session | Known admin actor, business hours, matching ticket | Verify ticket, close as authorised change |
| Software installation creating a service (`7045`) | Occurs during a known install, signed image in `Program Files`, parent is `msiexec.exe` | Verify signature and install window, close |
| Windows Update / management agents creating scheduled tasks | Task path under `\Microsoft\Windows\`, actor is SYSTEM | Exclude by task path prefix, never by "all 4698" |
| Backup software holding `SeBackupPrivilege` (`4672`) | Service account, consistent schedule | Documented allowlist |
| Legitimate elevation by an administrator (`4672` at every admin logon) | Normal, expected | Already de-prioritised to level 5 |

---

## 6. Investigation steps (SOC L1)

1. **Identify the change and the actor.** Which account gained privilege
   (`memberName`), and who granted it (`subjectUserName`)?
2. **Is the actor an administrator at all?** If a standard user performed the change, the
   escalation already happened before this event — go looking for *that*.
3. **Trace the actor's session.** Use `subjectLogonId` → 4624 to get logon type and source IP.
   Type 10 (RDP) or type 3 (network) from an unexpected source turns this into a remote
   intrusion investigation.
4. **Reconstruct the process chain.** Sysmon EID 1 in the minutes before: was it
   `net.exe localgroup administrators lab-svc-update /add`? What is its parent? What is the
   parent's parent? Keep walking until you reach `explorer.exe`, a service, or a remote
   execution source (`wmiprvse.exe`, `services.exe`).
5. **Read the task or service definition.** For 4698, read `taskContent` — the XML names the
   command and the principal. For 7045, read `imagePath`. A binary in `%TEMP%` running as
   SYSTEM is decisive.
6. **Check privileges granted** in 4672. `SeDebugPrivilege` appearing on a non-admin account is
   a red flag for credential access next.
7. **Look for what the privilege was used for.** LSASS handles (Sysmon EID 10, rule `100153`),
   registry hive access, new accounts, log clearing (1102).
8. **Check current state on the host:**

   ```powershell
   Get-LocalGroupMember -Group "Administrators"
   Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq 'SYSTEM' } |
       Select-Object TaskName, TaskPath, Date, Author
   Get-CimInstance Win32_Service | Where-Object { $_.PathName -notlike 'C:\Windows\*' } |
       Select-Object Name, PathName, StartMode, StartName
   whoami /priv
   ```
9. **Decide and document.**

**Wazuh Discover queries used**

```
rule.id:(100140 OR 100141 OR 100142 OR 100143 OR 100144 OR 100145 OR 100151)
data.win.system.eventID:(4732 OR 4728 OR 4672 OR 4698 OR 4697 OR 7045 OR 4719)
data.win.eventdata.memberName:*lab-svc-update*
data.win.eventdata.privilegeList:*SeDebugPrivilege*
rule.mitre.id:("T1548.002" OR "T1098.007" OR "T1053.005")
```

---

## 7. Recommended response

| Verdict | Action |
|---|---|
| **False positive** (authorised administration) | Record the ticket, tune by actor + task path, close as authorised change. |
| **True positive, privilege granted but unused** | Reverse the change (remove from group, delete the task/service), disable the affected account, identify and close the access path, preserve logs, monitor 72 h. |
| **True positive, privilege used** | **Escalate to IR immediately.** Assume administrative compromise of the host: isolate it, reset **all** credentials that touched it (including any domain credentials cached on it), preserve memory and disk if your process requires it, hunt the same IOCs across every endpoint, and plan a rebuild — a host that reached SYSTEM cannot be trusted after cleaning. |

**Hardening recommendations produced by this detection**

* Remove standard users from local `Administrators`; use just-in-time elevation instead.
* Set UAC to **"Always notify"** and enable *"Only elevate executables that are signed and
  validated"* where practical — this breaks several published UAC-bypass variants.
* Enable Windows LAPS so the local admin password is unique per host.
* Restrict who can create scheduled tasks and services; alert on every non-Microsoft `7045`.
* Forward `4719` and `1102` to the SIEM with the highest priority and never suppress them.
