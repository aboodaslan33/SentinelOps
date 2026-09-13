# PB-01 — Brute Force / Failed Authentication

**Triggers:** `100100` (L3), `100101` (L10), `100102` (L12), `100103` (L8), `100104` (L12)
**MITRE:** T1110, T1110.001, T1110.003 · **Detail:** [`brute-force.md`](../detection-rules/brute-force.md)

---

## 1. Detection

Windows Security **Event ID 4625** (failed logon) in volume from a single source, correlated by
Wazuh. Escalating variants: `100101` = many failures one account; `100104` = many failures many
accounts (spraying); `100102` = **failures followed by a success** — the one that matters most.

## 2. Initial triage (target: 5 minutes)

- [ ] Record: target account, source IP, logon type, host, first/last timestamp, count.
- [ ] **Logon type?** 3 = network/SMB, 10 = RDP. Type 10 from an unknown source is more urgent.
- [ ] **Sub-status?** `0xC000006A` = valid user, wrong password (**worse**). `0xC0000064` = user
      does not exist (enumeration).
- [ ] Is the source IP internal, known, or unexpected?
- [ ] Is the target account privileged? `Get-LocalGroupMember -Group "Administrators"`
- [ ] Check whether rule `100102` also fired → if yes, go straight to §6 Escalation.

## 3. Investigation

```
rule.id:(100100 OR 100101 OR 100102 OR 100104)
data.win.system.eventID:4625 AND data.win.eventdata.ipAddress:"<SRC_IP>"
data.win.system.eventID:4624 AND data.win.eventdata.ipAddress:"<SRC_IP>"      <- the key query
data.win.eventdata.targetUserName:"<ACCOUNT>"
```

1. **Did any attempt succeed?** Search 4624 for that IP and that account across the burst window
   **and the 30 minutes after**. This single answer sets the severity.
2. If a success exists → take its `logonId` and search for everything that session did
   (process creation, account changes, file access).
3. Check for a lockout (4740) and for other targeted accounts (spraying).
4. Check for follow-on activity on the host: 4720, 4732, 4698, 7045, 4104.
5. Check whether the same source is hitting other agents.
6. Contact the account owner: "were you trying to log in at HH:MM UTC?"

## 4. Evidence to collect

Alert IDs and rule IDs · full 4625 list (time, account, IP, type, sub-status) · the 4624 search
result **including a negative result** · account state (`net user <name>`) and group membership ·
lockout events · screenshot of the authentication timeline with the time range visible.

## 5. Containment (within L1 mandate)

```powershell
New-NetFirewallRule -DisplayName "IR-block-<TICKET>" -Direction Inbound -RemoteAddress <SRC_IP> -Action Block
Disable-LocalUser -Name "<ACCOUNT>"          # only if a successful logon is confirmed
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:30
```

Force a password reset on the targeted account. Do **not** delete accounts.

## 6. Escalation

Escalate to L2/IR immediately if **any** of these is true:

- a successful logon followed the failures (rule `100102`);
- the targeted account is privileged;
- multiple hosts or multiple accounts are affected (spraying);
- the source is external or unidentified;
- follow-on activity (new account, task, service, PowerShell) is present.

**Handover must contain:** timeline, source IP, targeted accounts, success/no-success with the
query used, actions already taken, open questions.

## 7. Closure

| Verdict | Close as |
|---|---|
| Known user / stale credential / scanner | False Positive — raise a tuning task, record the cause |
| Attack failed, source blocked, no success | True Positive — Contained |
| Success confirmed | **Do not close at L1** — escalate |

Before closing: confirm monitoring is extended for 72 h, record recommendations (lockout policy,
SMB/RDP exposure, MFA), and log one improvement (tuned threshold or new detection).
