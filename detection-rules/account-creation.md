# Detection 03 — New User Account Creation

> Laboratory detection. The accounts referenced below were created and deleted inside the
> isolated SentinelOps lab.

| Field | Value |
|---|---|
| **Detection name** | Unexpected Local Account Creation |
| **Detection ID** | SO-DET-003 |
| **Wazuh rules** | `100120`, `100121`, `100122`, `100123`, `100140` |
| **Data source** | Windows Security event log |
| **Windows Event IDs** | `4720` (user account created), `4722` (account enabled), `4724` (password reset attempt), `4738` (account changed), `4732` (member added to a security-enabled **local** group), `4726` (account deleted) |
| **Sysmon Event ID** | `1` — corroborating: `net.exe user /add`, `net localgroup administrators /add`, `New-LocalUser` |
| **Severity** | **Medium 8** (account created) → **High 13** (new account promoted to a privileged group) |
| **MITRE ATT&CK** | **TA0003 Persistence** — [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Create Account: Local Account; **TA0003/TA0004** — [T1098.007](https://attack.mitre.org/techniques/T1098/007/) Account Manipulation: Additional Local or Domain Groups; **TA0040 Impact** — [T1531](https://attack.mitre.org/techniques/T1531/) Account Access Removal (for 4726 where a legitimate account is removed) |

---

## 1. Why unexpected account creation is suspicious

An attacker who has code execution still has a problem: the moment the user reboots, closes the
malicious document, or the malware is cleaned, access is gone. A **local account is the cheapest,
most durable persistence there is**:

* it survives reboots, patching and antivirus cleanup;
* it does not look like malware to an endpoint product — `net user` is a signed Windows binary;
* if it is added to **Administrators**, it also delivers privilege escalation;
* if it is added to **Remote Desktop Users**, it delivers remote access;
* it blends in when it is named to look like a service (`svc-update`, `helpdesk`, `sqlsvc`,
  `admin2`, `DefaultAccount1`).

On a workstation in a small organisation, **account creation should be a rare, scheduled,
ticketed event.** Any account created outside that process deserves an investigation. That is
why `100120` is Medium (8) rather than informational — the base rate is low enough that a human
can afford to look at every one.

### The sequence that indicates an attack

```
4720  account created            "svc-update"
4722  account enabled            "svc-update"
4724  password set               "svc-update"
4732  added to Administrators    "svc-update"   <-- within seconds/minutes
4624  logon type 3 or 10 as      "svc-update"   <-- attacker uses the backdoor
```

Legitimate IT provisioning produces the same first three events — but usually during business
hours, from a known admin account, matching a ticket, and usually **not** immediately followed
by membership in `Administrators` and a remote logon.

---

## 2. Key fields

| Field | Wazuh field name | Meaning |
|---|---|---|
| New account name | `win.eventdata.targetUserName` | The account that was created |
| New account SID | `win.eventdata.targetSid` | Durable identifier — survives a rename |
| Creator account | `win.eventdata.subjectUserName` | **Who did it** — the most important field |
| Creator logon ID | `win.eventdata.subjectLogonId` | Links to the 4624 session that performed the action, so you can trace back to *how* they got in |
| Host | `win.system.computer` | Where |
| Time | `win.system.systemTime` | When |
| Group name (4732) | `win.eventdata.targetUserName` | The **group** the member was added to |
| Member added (4732) | `win.eventdata.memberName` / `memberSid` | The **account** that was added |

> **Field trap to know for interviews:** in Event ID **4732**, `TargetUserName` is the *group*,
> and the account being added is in `MemberName` / `MemberSid`. It is the opposite of 4720.
> Mixing these up produces rules that never fire.

---

## 3. Wazuh rules, explained

```xml
<rule id="100120" level="8">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4720$</field>
  <description>SentinelOps: Local user account $(win.eventdata.targetUserName) created on $(win.system.computer) by $(win.eventdata.subjectUserName)</description>
  <mitre><id>T1136.001</id></mitre>
</rule>
```

* Deliberately **not** filtered by username pattern. Rules that only alert on "suspicious
  looking" names fail the moment the attacker picks a boring name. Detect the *action*, filter
  the noise with tuning later.
* The description embeds both the new account and the creator, so the analyst gets the two
  questions that matter ("who was created, by whom") without opening the event.

```xml
<rule id="100121" level="13" timeframe="300">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4732$</field>
  <if_matched_sid>100120</if_matched_sid>
  <mitre><id>T1136.001</id><id>T1098.007</id></mitre>
</rule>
```

* **Correlation across two different event IDs.** `if_matched_sid` means "rule 100120 fired in
  the last 300 seconds"; the rule itself matches the 4732 that follows. Creation *plus*
  privilege within five minutes is the backdoor-admin pattern → level 13 (High).
* Two MITRE IDs because the behaviour genuinely spans two techniques: creating the account
  (T1136.001) and granting it group membership (T1098.007).

```xml
<rule id="100140" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4732$</field>
  <field name="win.eventdata.targetUserName">(?i)^Administrators$|^Remote Desktop Users$|^Backup Operators$|^Power Users$</field>
  <mitre><id>T1098.007</id></mitre>
</rule>
```

* Standalone privileged-group change, for the case where an **existing** account is promoted
  rather than a new one created. Anchored (`^...$`) so `Administrators` does not also match a
  custom group named `App-Administrators-ReadOnly`.

```xml
<rule id="100123" level="8">
  <field name="win.system.eventID">^4726$</field>
  <mitre><id>T1531</id></mitre>
</rule>
```

* Account deletion matters in two directions: an attacker cleaning up the backdoor they
  created, or a real user losing access (T1531 Account Access Removal). The MITRE mapping
  above is correct for the second case; when the deleted account is one the attacker created,
  treat it as indicator removal and say so in the incident report rather than forcing an ID.

---

## 4. Generating the telemetry in the lab (MANUAL STEP)

Use [`/scripts/New-LabTestAccount.ps1`](../scripts/New-LabTestAccount.ps1) — it creates a
clearly-labelled lab account, optionally adds it to a privileged group, and **removes it again**
so the lab is left clean.

```powershell
# Run as Administrator on WIN-SOC-EP01. LAB ONLY.
.\New-LabTestAccount.ps1 -AccountName lab-svc-update -AddToAdministrators -RemoveAfterSeconds 120
```

Prerequisite: **Audit User Account Management** and **Audit Security Group Management** enabled
for Success (see `/documentation/installation.md` §6).

---

## 5. False positives

| Cause | Recognition | Handling |
|---|---|---|
| IT provisioning a new starter | Business hours, known admin `subjectUserName`, matching ticket | Verify the ticket reference, close as authorised change |
| Application installer creating a service account | 4720 immediately preceded by an installer process (Sysmon EID 1 → `msiexec.exe`, setup binary) | Document the application, allowlist the specific account name |
| Windows itself creating `DefaultAccount`, `WDAGUtilityAccount` | `subjectUserName` is `SYSTEM`, occurs at OS install / feature enablement | Exclude these specific built-in names |
| MDM / Intune enrolment creating a local admin | Parent process is the management agent, occurs at enrolment | Allowlist by creator account and process |

---

## 6. Investigation steps (SOC L1)

1. **Read the alert:** new account name, creator account, host, timestamp.
2. **Is the creator expected?** If `subjectUserName` is a normal user rather than an
   administrator, that alone is an escalation trigger — a standard user should not be able to
   create accounts.
3. **Trace the creator's session.** Take `subjectLogonId` and find the matching 4624:

   ```
   data.win.eventdata.logonId:"0x3e7a1" AND data.win.system.eventID:4624
   ```
   That tells you the logon type and source IP — i.e. **how the actor got onto the host**.
   If it is logon type 3 or 10 from an unexpected IP, you now have two incidents linked.
4. **What ran just before?** Look at Sysmon EID 1 in the 5 minutes before the 4720. You should
   see either `net.exe user <name> <password> /add`, `net1.exe`, or PowerShell `New-LocalUser`.
   The *parent* of that process is the foothold.
5. **Check group membership** (4732/4728) for the new account. Administrators or Remote Desktop
   Users turns Medium into High.
6. **Has the account been used?** Search 4624 for `targetUserName:<new account>`. A logon means
   the backdoor is live.
7. **Check the account state on the host:**

   ```powershell
   Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, SID
   Get-LocalGroupMember -Group "Administrators"
   net user <accountname>
   ```
8. **Correlate with the change process.** Is there a ticket? Ask the IT owner directly.
9. **Decide and document.**

**Wazuh Discover queries used**

```
rule.id:(100120 OR 100121 OR 100122 OR 100123 OR 100140)
data.win.system.eventID:(4720 OR 4722 OR 4724 OR 4726 OR 4732 OR 4738)
data.win.eventdata.targetUserName:"lab-svc-update"
data.win.eventdata.subjectUserName:"lab-admin"
rule.mitre.id:"T1136.001"
```

---

## 7. Recommended response

| Verdict | Action |
|---|---|
| **False positive** (authorised provisioning) | Record the ticket number in the alert, close as authorised change. Consider allowlisting the provisioning account. |
| **True positive, account not yet used** | Disable the account immediately (do **not** delete it — it is evidence), remove it from privileged groups, identify and close the access path used to create it, capture the creator's session details, monitor. |
| **True positive, account already used to log on** | **Escalate to IR.** Treat the host as compromised: isolate, disable the account, reset every local credential, review everything the account's sessions did, and check every other endpoint for the same account name/SID pattern. |

**Preservation note:** disable rather than delete. Deleting the account destroys the SID linkage
that lets you attribute later events in the timeline.

**Hardening recommendations produced by this detection**

* Remove standard users from the local Administrators group (this is what makes the technique
  possible in the first place).
* Enable LAPS (Windows LAPS) so local admin passwords are unique per host.
* Alert on **every** 4720 on workstations — the base rate is low enough to review each one.
* Require account creation to go through a ticketed process so alerts can be matched to changes.
