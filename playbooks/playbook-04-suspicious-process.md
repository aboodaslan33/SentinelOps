# PB-04 — Suspicious Process Execution

**Triggers:** `100130` (L3), `100131` (L12), `100132` (L13), `100133` (L10), `100134` (L12)
**MITRE:** T1082, T1087.001, T1033, T1016, T1218, T1036.003 · **Detail:** [`suspicious-process.md`](../detection-rules/suspicious-process.md)

---

## 1. Detection

Sysmon **EID 1**. Four distinct patterns: a **burst of distinct discovery commands** (`100131`),
a **LOLBin used to download or proxy execution** (`100132`), **execution from a user-writable
staging directory** (`100133`), and a **renamed system binary** (`100134`).

## 2. Initial triage (target: 5 minutes)

Answer these five in order — most alerts resolve before question five:

- [ ] **Parent process** — is the chain plausible? (`winword.exe → cmd.exe` is not)
- [ ] **Image path** — `System32`/`Program Files` (real) vs `%TEMP%`/`Users\Public`/`Downloads`
      (suspicious)
- [ ] **Command line** — does it read like administration, or like `certutil -urlcache -f http://…`?
- [ ] **User + integrity level** — did a standard user's process run at `High`?
- [ ] **`originalFileName` vs `image`** — a mismatch is deliberate renaming. Verdict, not hint.

## 3. Investigation

```
rule.id:(100130 OR 100131 OR 100132 OR 100133 OR 100134)
data.win.eventdata.processGuid:"<GUID>"            # pivots to EID 3, 11, 22, 5
data.win.eventdata.parentImage:* AND agent.name:"<HOST>"
data.win.eventdata.image:*\\Users\\Public\\*
```

1. Rebuild the full process tree up to `explorer.exe`, a service, or a remote-execution parent.
2. List every process from that parent shell in the window — is it a **varied** sequence
   (reconnaissance) or the **same** command repeating (automation)?
3. Compare against the baseline: how many distinct discovery binaries per minute is normal here?
4. Hash the binary (`win.eventdata.hashes`) and check reputation. Unsigned binary in a user
   directory is decisive.
5. Network (EID 3) and DNS (EID 22) from the same `ProcessGuid` — did it reach out?
6. Files written (EID 11) — anything dropped into a staging directory?
7. What came next: accounts (4720), groups (4732), tasks (4698), services (7045), PowerShell (4104)?
8. Ask the user or the administrator — fastest disambiguation available.

## 4. Evidence to collect

Process image, full command line, parent image **and parent command line**, user, integrity
level, SHA256, PID/`ProcessGuid`, `originalFileName`, the ordered list of processes in the
burst, network/DNS/file activity, process lifetime, the relevant baseline figure.

## 5. Containment

```powershell
Stop-Process -Id <PID> -Force                          # capture details first
Get-FileHash "<path>" -Algorithm SHA256                # hash BEFORE removing
Move-Item "<path>" "C:\Lab\Evidence\<ticket>\"         # preserve, then remove from the live path
New-NetFirewallRule -DisplayName "IR-block-<TICKET>" -Direction Outbound -RemoteAddress <IP> -Action Block
Start-MpScan -ScanType FullScan
```

## 6. Escalation

Escalate to L2/IR if: a renamed or unsigned binary executed; a LOLBin downloaded content; the
process made an outbound connection or wrote executables; the activity progressed past
discovery; it ran elevated; or the same pattern appears on another host.

**Reconnaissance always implies prior execution.** The escalation question is not "what did
`whoami` do" — it is "how did the actor get the ability to run `whoami`?"

## 7. Closure

| Verdict | Close as |
|---|---|
| Logon/GPO script, inventory agent, helpdesk session, signed installer | False Positive — exclude by parent + exact command line |
| Recon only, no progression, host verified clean | True Positive — Contained (escalate the root-cause question) |
| Download / execution / persistence found | **Escalate** — do not close at L1 |

Record whether the baseline threshold needs adjusting, and the hardening actions (AppLocker/WDAC
on user-writable paths, ASR rules, command-line auditing).
