# Expected logtest results

> ## ⚠️ NOTHING HERE IS PROVEN
>
> This file states what **should** happen when each sample event is run through
> `wazuh-logtest`. **None of it has been executed** — the SentinelOps stack has not been
> built. The only thing that can prove a rule fires is [`run-logtest.sh`](run-logtest.sh),
> and it can only run on an installed Wazuh manager that already has
> `detection-rules/local_rules.xml` deployed. Treat every row below as a *prediction to be
> verified*, not a result. Rows whose rule carries `NEEDS-LOGTEST-VERIFICATION` in
> `local_rules.xml` are the ones most likely to need adjustment on first run (regex
> backslash count, engine behaviour, correlation windows).

## How the samples are framed

Each `<ruleid>.txt` holds one or more **Windows eventchannel JSON** lines in the
`{"win":{"system":{...},"eventdata":{...}}}` shape. This is the representation Wazuh
decodes into `win.system.*` / `win.eventdata.*`. The exact raw framing a given Wazuh
version expects from `wazuh-logtest` may differ slightly; if a sample does not decode,
adjust the wrapper, not the detection logic. Values such as host names and IPs are
**synthetic test inputs**, not captured data.

## Expected results per rule

| Rule | Expected level | Events fed | Key fields that must match | Notes |
|---|---|---|---|---|
| `100100` | 3 | 1 | win.system.eventID=4625; ipAddress; targetUserName; logonType | Base failed-logon event. |
| `100101` | 10 | 8 | 8x 4625 same ipAddress within timeframe | Correlation (frequency=8/120s, same_field ipAddress). Base 100100 also fires for earlier events. |
| `100102` | 12 | 9 | 4624 same ipAddress after a 100101 burst | 8x4625 then 1x4624 same IP. Depends on 100101 firing first in the same session. |
| `100103` | 8 | 1 | win.system.eventID=4740 | Account lockout. |
| `100104` | 12 | 10 | 10x 4625 same ipAddress, different targetUserName | Correlation (frequency=10/300s, different_field targetUserName). 100101 may also fire. |
| `100110` | 3 | 1 | sysmon EID1; originalFileName ~ powershell.exe | Base PowerShell launch (benign command line, parent explorer). |
| `100111` | 10 | 1 | sysmon EID1; image=powershell.exe; commandLine has -enc/-w hidden/bypass | originalFileName omitted so 100110 does not also match. |
| `100112` | 12 | 1 | sysmon EID1; parentImage=WINWORD.EXE; image=powershell.exe | Office parent spawns a shell. |
| `100113` | 12 | 1 | 4104; scriptBlockText has DownloadString/IEX | Script-block download cradle. |
| `100114` | 10 | 1 | sysmon EID3; image=powershell.exe; destinationIp/Port | Interpreter outbound connection. |
| `100115` | 13 | 1 | 4104; scriptBlockText has Set-MpPreference | Defence tampering in a script block. |
| `100120` | 8 | 1 | win.system.eventID=4720; targetUserName; subjectUserName | Local account created. |
| `100121` | 13 | 2 | 4732 after a 100120 within 300s | 4720 then 4732(memberName). 100120 fires first; 100140 also matches the 4732 (higher-level 100121 expected). |
| `100122` | 5 | 1 | win.system.eventID=4722|4724|4738 | Account enabled/reset/modified. |
| `100123` | 8 | 1 | win.system.eventID=4726 | Account deleted. |
| `100130` | 3 | 1 | sysmon EID1; image ~ discovery binary | Single discovery command. |
| `100131` | 12 | 5 | 5x sysmon EID1 same computer, different image | Correlation (frequency=5/60s, different_field image). Base 100130 also fires. |
| `100132` | 13 | 1 | sysmon EID1; commandLine certutil -urlcache http | LOLBin download. |
| `100133` | 10 | 1 | sysmon EID1; image under Users\Public | Execution from a staging directory. |
| `100134` | 12 | 1 | sysmon EID1; originalFileName=PowerShell.EXE; image != real powershell | Masquerade (negate on image). |
| `100140` | 12 | 1 | 4732; targetUserName=Administrators (no preceding 4720) | Privileged group change without a fresh account, so 100121 cannot fire. |
| `100141` | 5 | 1 | 4672; subjectUserName not SYSTEM/service/computer$ | Privileged logon context. |
| `100142` | 13 | 1 | sysmon EID1; parentImage=fodhelper.exe | UAC-bypass parent. |
| `100143` | 10 | 1 | win.system.eventID=4698 | Scheduled task created (Security). |
| `100144` | 12 | 1 | sysmon EID1; image=schtasks.exe; commandLine /create | Scheduled task from command line. |
| `100145` | 10 | 1 | win.system.eventID=7045 (System log) | Service installed. |
| `100150` | 14 | 1 | win.system.eventID=1102|104 | Event log cleared. |
| `100151` | 12 | 1 | win.system.eventID=4719 | Audit policy changed. |
| `100152` | 12 | 1 | providerName=Microsoft-Windows-Sysmon; eventID=4|16 | Sysmon service/config change. |
| `100153` | 14 | 1 | sysmon EID10; targetImage=lsass.exe; grantedAccess mask | LSASS handle access. |

## Correlation & sibling-overlap caveats

- **Correlation rules** (`100101`, `100102`, `100104`, `100121`, `100131`) only fire after
  the required number of prerequisite events in a **single** logtest session. The sample
  files already contain the full sequence, so feeding the whole file is what trips them.
- **Overlapping siblings**: some samples legitimately match more than one rule (e.g. the
  `100121` sample also satisfies `100140`; a real PowerShell launch matches both `100110`
  and `100111`). Wazuh reports one winning rule per event. `run-logtest.sh` prints the
  **actual** matched rule id(s) next to the expected one so a mismatch is visible rather
  than hidden. Where the winner differs from the target, decide whether to reorder rules,
  raise/lower a level, or accept the sibling — and record the decision.
- A **FAIL** from `run-logtest.sh` means exactly one thing: *this needs investigation on a
  live manager.* It does not by itself mean the rule is wrong or right.
