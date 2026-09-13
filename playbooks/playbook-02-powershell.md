# PB-02 — Suspicious PowerShell

**Triggers:** `100110` (L3), `100111` (L10), `100112` (L12), `100113` (L12), `100114` (L10), `100115` (L13)
**MITRE:** T1059.001, T1027.010, T1105, T1204.002, T1562.001 · **Detail:** [`powershell.md`](../detection-rules/powershell.md)

---

## 1. Detection

Sysmon **EID 1** (command line with `-enc`, `-w hidden`, `-ExecutionPolicy Bypass`), PowerShell
**Event ID 4104** (de-obfuscated script block containing a download cradle), Sysmon **EID 3**
(interpreter making an outbound connection).

## 2. Initial triage (target: 5 minutes)

- [ ] Read the full command line from the alert.
- [ ] **Is it Base64?** Decode it **offline** — decoding is not executing.
- [ ] **Who is the parent?** `explorer.exe` (user action) vs `winword.exe`/`outlook.exe`
      (**phishing — treat as High immediately**) vs `services.exe`/`wmiprvse.exe`
      (**remote execution — treat as lateral movement**).
- [ ] Which user, and did it run elevated (`integrityLevel`)?
- [ ] Did rule `100113` (download cradle) or `100115` (defence tampering) also fire?

```powershell
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<BASE64>'))
```

## 3. Investigation

```
rule.id:(100110 OR 100111 OR 100112 OR 100113 OR 100114 OR 100115)
data.win.system.eventID:4104 AND agent.name:"<HOST>"
data.win.eventdata.processGuid:"<GUID>"        # pivots to EID 3 (network), 11 (files), 22 (DNS), 5 (exit)
data.win.eventdata.parentImage:*
```

1. Get the **decoded intent** from Event 4104 — this is the authoritative record of what ran.
2. Build the process tree upward until you reach `explorer.exe`, a service, or a remote source.
3. Network: any Sysmon EID 3 from the same `ProcessGuid`? Record destination IP/port. Any EID 22
   DNS query? Record the domain.
4. Files: any EID 11 writes? Record path + SHA256.
5. **Did it only download, or download *and execute*?** Look for `IEX`/`Invoke-Expression`
   applied to the retrieved content, and for child processes.
6. Persistence: Run keys (EID 12/13), Startup folder, 4698, 7045, 4720.
7. Ask the user: "did you run a script at HH:MM UTC?"

## 4. Evidence to collect

Full command line · **decoded** script block text (4104) · process tree with PIDs/GUIDs and
parent command lines · destination IP/domain/URL · dropped file paths + SHA256 · user and
integrity level · process lifetime (EID 1 → EID 5) · screenshots.

## 5. Containment

```powershell
Stop-Process -Id <PID> -Force                  # capture details first
New-NetFirewallRule -DisplayName "IR-block-<TICKET>" -Direction Outbound -RemoteAddress <IP> -Action Block
Get-FileHash <dropped file> -Algorithm SHA256  # hash BEFORE removing
Start-MpScan -ScanType FullScan
```

If persistence exists or the parent was an Office application → isolate the host.

## 6. Escalation

Escalate to L2/IR if: code was downloaded **and executed**; the parent was an Office/mail
application; the process ran elevated; persistence was created; defences or logs were tampered
with (`100115`); or the same command line appears on more than one host.

## 7. Closure

| Verdict | Close as |
|---|---|
| Management agent / signed installer / known admin script | False Positive — narrow exclusion by parent image + script path, documented |
| Download attempted, nothing executed, host clean | True Positive — Contained |
| Execution confirmed | **Escalate** — do not close at L1 |

Record IOCs for hunting, and raise the hardening actions (ASR rules, Constrained Language Mode,
remove PowerShell v2, AppLocker on `%TEMP%`).
