# Automation Scripts

> **LAB ONLY — SAFE BY DESIGN.** Every script in this folder is a *defensive* testing tool. It
> generates the **telemetry** that a technique produces, using benign commands, so that the
> SentinelOps detection rules can be validated end to end. None of these scripts contain
> malware, exploits, real payloads, persistence, credential theft, or destructive actions, and
> none target any system other than the lab VM you name.

Run them only on virtual machines you own, on an isolated host-only network, with the NAT
adapter disabled (see [`/documentation/installation.md`](../documentation/installation.md) §2).

---

## Scripts

| Script | Purpose | Rules validated | Telemetry produced | Run on |
|---|---|---|---|---|
| [`Invoke-LabFailedLogons.ps1`](Invoke-LabFailedLogons.ps1) | Generate failed SMB logons | `100100`, `100101`, `100104` | Security 4625 | `LAB-ATTACK01` (or locally) |
| [`Invoke-LabPowerShellActivity.ps1`](Invoke-LabPowerShellActivity.ps1) | Encoded / hidden / cradle PowerShell | `100110`, `100111`, `100113`, `100114` | Sysmon EID 1, PowerShell 4104, Sysmon EID 3 | `WIN-SOC-EP01` |
| [`New-LabTestAccount.ps1`](New-LabTestAccount.ps1) | Create/promote/remove a test account | `100120`, `100121`, `100140` | Security 4720/4722/4724/4732/4726 | `WIN-SOC-EP01` (elevated) |
| [`Invoke-LabSuspiciousProcess.ps1`](Invoke-LabSuspiciousProcess.ps1) | Recon burst, staging-dir exec, masquerade | `100130`, `100131`, `100133`, `100134` | Sysmon EID 1 | `WIN-SOC-EP01` |
| [`Invoke-LabPrivilegeActivity.ps1`](Invoke-LabPrivilegeActivity.ps1) | Group change, SYSTEM task, priv logon | `100140`, `100141`, `100143`, `100144` | Security 4732/4672/4698, Sysmon EID 1 | `WIN-SOC-EP01` (elevated) |
| [`Get-LabEventSummary.ps1`](Get-LabEventSummary.ps1) | **Read-only** telemetry summary | — | none (reads logs) | `WIN-SOC-EP01` |

---

## Prerequisites

1. **Execution policy** for the current session (does not change the system permanently):

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```

2. **Audit policy** applied — [`installation.md`](../documentation/installation.md) §6.
3. **PowerShell script block logging** enabled — §7.
4. **Sysmon** installed with this repo's config — [`/sysmon/README.md`](../sysmon/README.md).
5. **Wazuh agent** Active and collecting the right channels — §5, §9.

---

## Recommended test run

```powershell
# On WIN-SOC-EP01, revert to the 04-pre-simulation snapshot first for a clean baseline.

# 1. Confirm telemetry is flowing (read-only)
.\Get-LabEventSummary.ps1 -Hours 1

# 2. Brute force (from LAB-ATTACK01, or locally against 127.0.0.1)
.\Invoke-LabFailedLogons.ps1 -TargetHost 192.168.56.20 -UserName svc-backup -Attempts 12 -DelaySeconds 3

# 3. PowerShell
.\Invoke-LabPowerShellActivity.ps1 -Scenario All

# 4. Account creation + escalation
.\New-LabTestAccount.ps1 -AccountName lab-svc-update -AddToAdministrators -RemoveAfterSeconds 120

# 5. Suspicious process
.\Invoke-LabSuspiciousProcess.ps1 -Scenario All

# 6. Privilege activity (self-cleaning)
.\Invoke-LabPrivilegeActivity.ps1 -AccountName lab-svc-update -CleanUp

# 7. Confirm what was produced
.\Get-LabEventSummary.ps1 -Hours 1
```

Then confirm each detection on the Wazuh Dashboard using the queries printed by each script.

---

## Safety design notes

| Concern | How these scripts address it |
|---|---|
| Attacking a real host | Failed-logon script guards against non-lab targets and asks for confirmation |
| Real credential guessing | The password is always deliberately **wrong**; nothing is guessed |
| Leaving a backdoor | Account/task scripts require a `lab-` name prefix and support automatic cleanup |
| Real malware/payloads | The "download cradle" is text logged for 4104; any real fetch is from a **local lab** server only |
| Destructive change | Scripts only add and then reverse; the read-only summary changes nothing |
| Password exposure | Random throwaway passwords are generated in memory and never written to disk or logs |

> **Optional lab web server** for the PowerShell download demo (run on `LAB-ATTACK01`):
> ```powershell
> # Serves the current directory on port 8000 - LAB ONLY, stop it when done.
> cd C:\Lab\www ; python -m http.server 8000
> ```
> Place a harmless `lab-test.txt` in that directory. Never expose this beyond the host-only network.
