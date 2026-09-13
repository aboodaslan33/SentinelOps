# PB-03 — New Account Creation

**Triggers:** `100120` (L8), `100121` (L13), `100122` (L5), `100123` (L8), `100140` (L12)
**MITRE:** T1136.001, T1098, T1098.007 · **Detail:** [`account-creation.md`](../detection-rules/account-creation.md)

---

## 1. Detection

Windows Security **4720** (account created), **4722/4724** (enabled / password set), **4732**
(added to a local group), **4726** (deleted). The High-severity case is `100121`: creation
**and** privileged group membership within five minutes.

## 2. Initial triage (target: 5 minutes)

- [ ] Record: new account name, **creator account** (`subjectUserName`), host, timestamp.
- [ ] Is there a change ticket for this? No ticket = treat as unauthorised.
- [ ] Is the creator an administrator? If a **standard user** created an account, escalation
      already happened — investigate that first.
- [ ] Did `100121`/`100140` also fire (privileged group)? → High.
- [ ] Does the name mimic a service account (`svc-`, `admin2`, `update`)? Camouflage is a signal,
      but its absence proves nothing.

## 3. Investigation

```
rule.id:(100120 OR 100121 OR 100122 OR 100123 OR 100140)
data.win.system.eventID:(4720 OR 4722 OR 4724 OR 4726 OR 4732)
data.win.eventdata.targetUserName:"<NEW_ACCOUNT>"
data.win.eventdata.logonId:"<SUBJECT_LOGON_ID>" AND data.win.system.eventID:4624   <- the key pivot
```

1. **Pivot on `subjectLogonId` → 4624.** This gives the logon **type** and **source IP** of the
   session that created the account, i.e. how the actor got onto the host. A type 3 or 10 logon
   from an unexpected IP turns this into a remote-intrusion investigation.
2. Sysmon EID 1 in the 5 minutes before: find `net user … /add`, `net1.exe`, or `New-LocalUser`,
   and walk the parent chain up to its root.
3. Group membership: is the new account in Administrators or Remote Desktop Users?
4. **Has the account logged on?** `4624` for `targetUserName:<new account>`. A logon means the
   backdoor is live.
5. Other persistence on the host: 4698, 7045, Run keys, WMI subscriptions.
6. Compare `Get-LocalUser` against the baseline list.

```powershell
Get-LocalUser | Select Name, Enabled, LastLogon, PasswordLastSet, SID
Get-LocalGroupMember -Group "Administrators"
```

## 4. Evidence to collect

4720 + 4732 raw events · account **SID** · creator account and logon ID · the 4624 for that
logon (type + source IP) · the process and command line that created the account · current
`Get-LocalUser` / `Get-LocalGroupMember` output · whether the account has ever authenticated.

## 5. Containment

```powershell
Disable-LocalUser -Name "<NEW_ACCOUNT>"                                    # disable, DO NOT delete
Remove-LocalGroupMember -Group "Administrators" -Member "<NEW_ACCOUNT>"
# Rotate the credential of the account that created it:
Set-LocalUser -Name "<CREATOR>" -Password (Read-Host -AsSecureString)
```

Delete the account only **after** evidence capture and investigation are complete — the SID is
needed to attribute later events.

## 6. Escalation

Escalate to L2/IR if: the creation was unauthorised; the creating session was **remote**; the
account is privileged; the account has already been used to log on; other persistence exists;
or the same account name appears on another host.

## 7. Closure

| Verdict | Close as |
|---|---|
| Provisioning with a matching ticket / known installer / built-in Windows account | False Positive — record the ticket, allowlist narrowly |
| Unauthorised account created but never used, now disabled and removed | True Positive — Eradicated |
| Account used to authenticate | **Escalate** — do not close at L1 |

Record the root-cause question explicitly: *how did the actor obtain the credential that
created the account?* Account creation is almost always the second step, never the first.
