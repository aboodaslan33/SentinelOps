# PB-05 — Privilege Escalation

**Triggers:** `100140` (L12), `100141` (L5), `100142` (L13), `100143` (L10), `100144` (L12), `100145` (L10), `100151` (L12)
**MITRE:** T1098.007, T1548.002, T1053.005, T1543.003, T1078.003, T1562.002 · **Detail:** [`privilege-escalation.md`](../detection-rules/privilege-escalation.md)

---

## 1. Detection

Windows Security **4732** (privileged group change), **4672** (special privileges assigned),
**4698** (scheduled task created), **4697**/System **7045** (service installed), **4719** (audit
policy changed); Sysmon **EID 1** for `schtasks.exe`, `sc.exe`, `net localgroup`, and child
processes under auto-elevating binaries (`fodhelper.exe`, `computerdefaults.exe`, `sdclt.exe`).

## 2. Initial triage (target: 5 minutes)

- [ ] **What changed, and for whom?** In 4732: `TargetUserName` = **group**,
      `MemberName` = **account added**, `SubjectUserName` = **actor**. Do not mix these up.
- [ ] Was the actor already an administrator? If **not**, the escalation happened earlier —
      find that first.
- [ ] For 4698/7045: read the **task XML / service image path**. Does it run as **SYSTEM**?
      Does it trigger at **boot/logon**? Is the binary in `%TEMP%` or `Users\Public`?
- [ ] Is there a change ticket?
- [ ] Did `100152` (Sysmon tampering) or `100150`/`100151` (log/audit policy) also fire?
      → treat as attempted evasion, raise severity.

## 3. Investigation

```
rule.id:(100140 OR 100141 OR 100142 OR 100143 OR 100144 OR 100145 OR 100151)
data.win.system.eventID:(4732 OR 4672 OR 4698 OR 4697 OR 7045 OR 4719)
data.win.eventdata.logonId:"<SUBJECT_LOGON_ID>" AND data.win.system.eventID:4624
data.win.eventdata.privilegeList:*SeDebugPrivilege*
```

1. **Pivot on the actor's `logonId` → 4624**: logon type and source. Type 2 (console) vs type 3/10
   (remote) changes the whole investigation.
2. Rebuild the process chain that made the change (Sysmon EID 1 → parent → parent).
3. **Read the definition, not just the name:** task XML (principal `S-1-5-18` = SYSTEM, trigger),
   service `imagePath` and `startName`.
4. Has the escalated account been used? `4624` for that account.
5. **Was the privilege used?** Check `100153` / Sysmon EID 10 for LSASS handles,
   EID 8 (CreateRemoteThread), registry hive access. Record the answer either way.
6. Look for additional persistence: other tasks, services, Run keys, WMI subscriptions, accounts.
7. Verify the sensor is intact: `Sysmon64.exe -c`, `auditpol /get /category:*`.

```powershell
Get-LocalGroupMember -Group "Administrators"
Get-ScheduledTask | ? { $_.Principal.UserId -eq 'SYSTEM' } | Select TaskName, TaskPath, Author
Get-CimInstance Win32_Service | ? PathName -notlike 'C:\Windows\*' | Select Name, PathName, StartName
whoami /priv
```

## 4. Evidence to collect

4732 (group, member, actor) · 4672 `privilegeList` · **exported task XML** / service definition ·
the actor's 4624 (type + source IP) · process chain with command lines · integrity levels ·
current group/task/service state vs baseline · whether the privilege was exercised.

## 5. Containment

```powershell
Disable-ScheduledTask -TaskName "<TASK>"                # export XML first
Remove-LocalGroupMember -Group "Administrators" -Member "<ACCOUNT>"
Disable-LocalUser -Name "<ACCOUNT>"
sc.exe stop "<SERVICE>"                                 # capture imagePath first
# Rotate every credential used on this host, including cached domain credentials
```

Isolate the host if SYSTEM-level persistence was created or the privilege was exercised.

## 6. Escalation

**Escalate to L2/IR immediately — do not complete the investigation first — if:**
privilege was gained without a change ticket; a SYSTEM-level task or service was created; a UAC
bypass pattern fired (`100142`); the actor's session was remote; LSASS was accessed; logging or
Sysmon was tampered with; or more than one host is affected.

**A host where an actor reached SYSTEM cannot be proven clean.** The default recommendation is
rebuild; cleaning is a business risk-acceptance decision, and must be recorded as one.

## 7. Closure

| Verdict | Close as |
|---|---|
| Ticketed administration / signed installer service / Microsoft-path scheduled task | False Positive — exclude by actor + task path, documented |
| Unauthorised change reversed, privilege never exercised, host verified | True Positive — Eradicated |
| Privilege exercised, or SYSTEM persistence created | **Escalate** — do not close at L1 |

Always record the root cause: *how did the actor obtain administrative privilege in the first
place?* That question, not the group change, is the actual incident.
