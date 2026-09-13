# MITRE ATT&CK Mapping

Every detection in SentinelOps is mapped to a technique in **MITRE ATT&CK for Enterprise**.

> **Accuracy statement.** Technique IDs below were checked against
> [attack.mitre.org](https://attack.mitre.org/). Where a technique appears under more than one
> tactic, the tactic listed is the one that matches how the behaviour is observed **in this
> lab**. Technique names occasionally change between ATT&CK versions; the **ID is
> authoritative** — always follow the link rather than the name.

---

## 1. Master mapping table

| # | Detection (rule) | Tactic | Technique ID | Technique name | Detection source | Evidence observed | Investigation method |
|---|---|---|---|---|---|---|---|
| 1 | Failed logon (`100100`) | Credential Access (TA0006) | [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Windows Security log | Event 4625: target user, source IP, logon type, sub-status | Count failures per source IP; read `subStatus` to separate wrong-password from unknown-user |
| 2 | Brute force burst (`100101`) | Credential Access (TA0006) | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing | Windows Security log + Wazuh correlation | 8+ × 4625 from one IP in 120 s | Correlate on `same_field ipAddress`; then search 4624 for a success |
| 3 | Password spraying (`100104`) | Credential Access (TA0006) | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password Spraying | Windows Security log + Wazuh correlation | 4625 against many distinct usernames from one IP | Correlate `same_field ipAddress` with `different_field targetUserName` |
| 4 | Successful logon after brute force (`100102`) | Defense Evasion / Persistence / Privilege Escalation / Initial Access | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Valid Accounts: Local Accounts | Windows Security log | 4624 from the same IP as the failure burst | Pivot on `logonId` to everything the session did |
| 5 | PowerShell execution (`100110`, `100111`) | Execution (TA0002) | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | Sysmon EID 1 | Image, full command line, parent image, user | Decode Base64 offline; build the process tree from `ParentProcessGuid` |
| 6 | Encoded / hidden command line (`100111`) | Defense Evasion (TA0005) | [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | Obfuscated Files or Information: Command Obfuscation | Sysmon EID 1 | `-enc`, `-w hidden`, `-ExecutionPolicy Bypass` in the command line | Decode the Base64; compare with the 4104 script block |
| 7 | Office / script host spawns a shell (`100112`) | Execution (TA0002) | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Malicious File | Sysmon EID 1 | `parentImage` = `winword.exe`/`excel.exe`/`mshta.exe`, child = shell | Identify the document; check Sysmon EID 11 for the file written; interview the user |
| 8 | Download cradle in script block (`100113`) | Command and Control (TA0011) | [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | PowerShell Operational 4104, Sysmon EID 3 / 22 | `DownloadString`, `Invoke-WebRequest`, `Net.WebClient` in decoded text; outbound connection | Extract URL/IP from the script block; confirm with Sysmon EID 3 and DNS EID 22 |
| 9 | Defence tampering from PowerShell (`100115`) | Defense Evasion (TA0005) | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools | PowerShell 4104, Sysmon EID 1 | `Set-MpPreference`, `Add-MpPreference -ExclusionPath` | Check Defender status and exclusion list on the host |
| 10 | Local account created (`100120`) | Persistence (TA0003) | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Create Account: Local Account | Windows Security log | 4720: new account name, SID, creator, timestamp | Trace `subjectLogonId` to the 4624 that created the session |
| 11 | Account added to a privileged group (`100121`, `100140`) | Persistence (TA0003) / Privilege Escalation (TA0004) | [T1098.007](https://attack.mitre.org/techniques/T1098/007/) | Account Manipulation: Additional Local or Domain Groups | Windows Security log | 4732: group in `targetUserName`, member in `memberName` | Check `Get-LocalGroupMember Administrators`; correlate with the 4720 |
| 12 | Account modified / enabled (`100122`) | Persistence (TA0003) | [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Windows Security log | 4722 / 4724 / 4738 | Compare with the change record; check who performed it |
| 13 | Account deleted (`100123`) | Impact (TA0040) | [T1531](https://attack.mitre.org/techniques/T1531/) | Account Access Removal | Windows Security log | 4726: deleted account, actor | Determine whether a legitimate user lost access (T1531) or an attacker removed their own backdoor (indicator removal) |
| 14 | Discovery commands (`100130`, `100131`) | Discovery (TA0007) | [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | Sysmon EID 1 | `systeminfo.exe`, `hostname`, `tasklist.exe` | Look for a burst of distinct binaries from one parent shell |
| 15 | Account enumeration (`100131`) | Discovery (TA0007) | [T1087.001](https://attack.mitre.org/techniques/T1087/001/) | Account Discovery: Local Account | Sysmon EID 1 | `net user`, `net localgroup administrators` | Read the command line; check `net1.exe` as well as `net.exe` |
| 16 | User context enumeration (`100131`) | Discovery (TA0007) | [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | Sysmon EID 1 | `whoami /all`, `quser.exe` | Same process tree as #14/#15 |
| 17 | Network configuration enumeration (`100131`) | Discovery (TA0007) | [T1016](https://attack.mitre.org/techniques/T1016/) | System Network Configuration Discovery | Sysmon EID 1 | `ipconfig /all`, `arp -a`, `route print`, `netstat` | Same process tree; note whether the actor then connected somewhere |
| 18 | LOLBin download / proxy execution (`100132`) | Defense Evasion (TA0005) | [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution | Sysmon EID 1 + EID 3 | `certutil -urlcache`, `bitsadmin /transfer`, `mshta http…`, `regsvr32 /i:http` | Extract the URL; check Sysmon EID 11 for the downloaded file and hash it |
| 19 | Renamed system binary (`100134`) | Defense Evasion (TA0005) | [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | Masquerading: Rename System Utility | Sysmon EID 1 | `image` disagrees with `originalFileName` | Hash the file and compare with the genuine binary |
| 20 | UAC bypass pattern (`100142`) | Privilege Escalation (TA0004) / Defense Evasion (TA0005) | [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Abuse Elevation Control Mechanism: Bypass User Account Control | Sysmon EID 1 + EID 13 | Child process under `fodhelper.exe` / `computerdefaults.exe` / `sdclt.exe`; registry write to the hijacked command key | Check the registry key value; check the child's integrity level (`High`) |
| 21 | Scheduled task created (`100143`, `100144`) | Execution (TA0002) / Persistence (TA0003) / Privilege Escalation (TA0004) | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task/Job: Scheduled Task | Security 4698, Sysmon EID 1 | Task name, task XML (command + principal), `schtasks /create /ru SYSTEM` | Read the task XML; `Get-ScheduledTask` on the host |
| 22 | Service installed (`100145`) | Persistence (TA0003) / Privilege Escalation (TA0004) | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Create or Modify System Process: Windows Service | System 7045, Security 4697 | Service name, image path, start type, account | Check the image path location and signature |
| 23 | Administrative privileges assigned (`100141`) | Privilege Escalation (TA0004) | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Valid Accounts: Local Accounts | Windows Security log | 4672 with `privilegeList` (e.g. `SeDebugPrivilege`) | Correlate with the 4624 for the same `logonId` |
| 24 | Event log cleared (`100150`) | Defense Evasion (TA0005) | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Indicator Removal: Clear Windows Event Logs | Security 1102 / System 104 | The clearing event itself, with the account that did it | Identify the gap in the timeline; rely on SIEM-side copies already shipped |
| 25 | Audit policy changed (`100151`) | Defense Evasion (TA0005) | [T1562.002](https://attack.mitre.org/techniques/T1562/002/) | Impair Defenses: Disable Windows Event Logging | Security 4719 | Subcategory changed, actor | `auditpol /get /category:*` to confirm current state |
| 26 | Sysmon service/config changed (`100152`) | Defense Evasion (TA0005) | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools | Sysmon EID 4 / 16 | Service state change or config change event | Verify the active config with `Sysmon64.exe -c` |
| 27 | LSASS handle access (`100153`) | Credential Access (TA0006) | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | OS Credential Dumping: LSASS Memory | Sysmon EID 10 | `targetImage` = `lsass.exe`, `grantedAccess` mask, source image | Identify and hash the source process; treat as confirmed compromise until disproved |

---

## 2. Coverage by tactic

| Tactic | Techniques detected | Rules |
|---|---|---|
| Initial Access (TA0001) | T1078.003 (via valid-account use) | `100102` |
| Execution (TA0002) | T1059.001, T1204.002, T1053.005 | `100110`–`100113`, `100143`, `100144` |
| Persistence (TA0003) | T1136.001, T1098, T1098.007, T1053.005, T1543.003 | `100120`–`100122`, `100140`, `100143`–`100145` |
| Privilege Escalation (TA0004) | T1548.002, T1098.007, T1078.003, T1053.005, T1543.003 | `100140`–`100145` |
| Defense Evasion (TA0005) | T1027.010, T1218, T1036.003, T1562.001, T1562.002, T1070.001 | `100111`, `100115`, `100132`, `100134`, `100150`–`100152` |
| Credential Access (TA0006) | T1110, T1110.001, T1110.003, T1003.001 | `100100`–`100104`, `100153` |
| Discovery (TA0007) | T1082, T1087.001, T1033, T1016 | `100130`, `100131` |
| Command and Control (TA0011) | T1105 | `100113`, `100114`, `100132` |
| Impact (TA0040) | T1531 | `100123` |

**Nine of the fourteen Enterprise tactics have at least one working detection.**

---

## 3. Coverage gaps (stated honestly)

| Tactic | Why it is not covered in this lab |
|---|---|
| **Reconnaissance (TA0043)** / **Resource Development (TA0042)** | Pre-compromise, occurs on attacker infrastructure — not observable from an endpoint |
| **Lateral Movement (TA0008)** | Only one monitored endpoint. The Sysmon config already collects the relevant telemetry (named pipes EID 17/18, EID 3 to 445/3389/5985), so this is a lab-size limitation, not a sensor limitation |
| **Collection (TA0009)** | Would need file-access auditing and screen/clipboard capture telemetry, deliberately not enabled (noise and privacy) |
| **Exfiltration (TA0010)** | Requires network flow / proxy / DLP telemetry that this lab does not have |
| **Impact (TA0040)** beyond T1531 | Ransomware-style impact detection needs mass file-modification telemetry (Sysmon EID 11 at volume, or FIM tuned for it) |

Listing gaps is deliberate. A portfolio that claims full ATT&CK coverage from one workstation
is not credible; naming the limits of your telemetry is a core detection-engineering skill.

---

## 4. Using the ATT&CK Navigator (optional, MANUAL STEP)

1. Open the MITRE ATT&CK Navigator (`https://mitre-attack.github.io/attack-navigator/`).
2. *Create New Layer → Enterprise ATT&CK*.
3. Select each technique from the table above and set a score (e.g. 1 = detection exists).
4. *Layer Controls → Download → JSON*, and save it as `documentation/sentinelops-navigator-layer.json`.
5. Add a screenshot of the highlighted matrix to `/screenshots` as `08-mitre-attack-mapping.png`.

This produces the heat-map image that makes coverage instantly readable on a portfolio page.

---

## 5. Wazuh's built-in ATT&CK view

Wazuh maps alerts to ATT&CK automatically when a rule contains a `<mitre>` block:

```xml
<mitre>
  <id>T1110.001</id>
</mitre>
```

* ☰ → **MITRE ATT&CK → Framework** — the matrix, with detected techniques highlighted.
* ☰ → **MITRE ATT&CK → Intelligence** — technique details, mitigations, references.
* In *Discover*, query by technique directly:

```
rule.mitre.id: "T1059.001"
rule.mitre.tactic: "Credential Access"
rule.mitre.id: ("T1110" or "T1110.001" or "T1110.003")
```

If a technique ID does not exist in the ATT&CK database bundled with your Wazuh build, the
manager logs an error at startup and the mapping is dropped — which is a useful, if blunt,
validation that your IDs are real.
