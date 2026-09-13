# Detection 02 — Suspicious PowerShell Activity

> Laboratory detection. All commands shown are benign lab test commands. No malware, no real
> payloads, no external infrastructure.

| Field | Value |
|---|---|
| **Detection name** | Suspicious PowerShell Execution |
| **Detection ID** | SO-DET-002 |
| **Wazuh rules** | `100110`, `100111`, `100112`, `100113`, `100114`, `100115` |
| **Data source** | Sysmon Operational log + `Microsoft-Windows-PowerShell/Operational` |
| **Windows Event IDs** | `4104` (script block logging), `4103` (module/pipeline logging), `4688` (process creation, fallback) |
| **Sysmon Event IDs** | `1` (process creation), `3` (network connection), `11` (file created) |
| **Severity** | Informational 3 (any PowerShell) → **Medium 10** (suspicious switches) → **High 12–13** (download cradle, Office parent, defence tampering) |
| **MITRE ATT&CK** | **TA0002 Execution** — [T1059.001](https://attack.mitre.org/techniques/T1059/001/) PowerShell; **TA0005 Defense Evasion** — [T1027.010](https://attack.mitre.org/techniques/T1027/010/) Command Obfuscation, [T1562.001](https://attack.mitre.org/techniques/T1562/001/) Disable or Modify Tools; **TA0011 C2** — [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer; **TA0001/TA0002** — [T1204.002](https://attack.mitre.org/techniques/T1204/002/) User Execution: Malicious File |

---

## 1. Description

PowerShell is signed, installed everywhere, trusted by default and can download and execute
code entirely in memory. That is exactly why attackers use it — and why "powershell.exe ran"
is useless as an alert on its own. Detection has to be based on **how** it ran:

| Signal | Why it matters |
|---|---|
| `-EncodedCommand` / `-enc` | Base64 hides the command from the command line. Legitimate admin scripts almost never need it. |
| `-WindowStyle Hidden` / `-w hidden` | Interactive users do not hide their own console. |
| `-ExecutionPolicy Bypass` / `-nop` | Deliberately sidesteps local script controls. Execution policy is not a security boundary — but *bypassing* it is an intent signal. |
| `Net.WebClient` / `DownloadString` / `IEX` | The download cradle: fetch remote code and run it in memory, never touching disk. |
| Parent is `winword.exe` / `excel.exe` / `outlook.exe` | Documents do not need a shell. This is the phishing execution chain. |
| PowerShell making a network connection | Corroborates a download. |
| `Set-MpPreference` / `wevtutil cl` | Defence evasion. |

> **Abbreviation note.** PowerShell accepts any unambiguous prefix of a parameter name, so
> `-EncodedCommand`, `-enc`, `-ec` and `-e` are all the same switch. The rule regex covers the
> short forms on purpose — matching only the full parameter name is a trivially bypassed rule.

---

## 2. Why script block logging matters more than the command line

Command-line telemetry (Sysmon EID 1) shows you this:

```
powershell.exe -nop -w hidden -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==
```

Script block logging (Event ID **4104**) shows you the **decoded** content that was actually
executed, after PowerShell has expanded it:

```
Invoke-WebRequest -Uri http://192.168.56.30:8000/lab-test.txt -OutFile $env:TEMP\lab-test.txt
```

That is the difference between "something encoded ran" and a complete IOC list. **Enable
script block logging** (`/documentation/installation.md` §7) — it is the single highest-value
configuration change in this whole lab.

| Event ID | Log | Content |
|---|---|---|
| 4103 | PowerShell/Operational | Module/pipeline execution details |
| **4104** | PowerShell/Operational | **De-obfuscated script block text** |
| 4105 / 4106 | PowerShell/Operational | Script start / stop (very noisy, usually left off) |
| 400 / 403 | Windows PowerShell (classic) | Engine start/stop, shows `HostApplication` — useful on older hosts |

---

## 3. Wazuh rules, explained

```xml
<rule id="100111" level="10">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image">(?i)\\powershell\.exe|\\pwsh\.exe</field>
  <field name="win.eventdata.commandLine">(?i)-enc|-encodedcommand|-e |-ec |-w hidden|-windowstyle hidden|-nop|-noprofile|-exec bypass|-executionpolicy bypass|-nonI</field>
  <mitre><id>T1059.001</id><id>T1027.010</id></mitre>
</rule>
```

* `<if_group>sysmon_event1</if_group>` — child of the built-in Sysmon *process creation* rule.
  (Sysmon groups are `sysmon_event1`…`sysmon_event9`, then `sysmon_event_10` upward — the
  underscore quirk is in the Wazuh ruleset itself.)
* Two `<field>` elements = **AND**. Both the image and the command line must match.
* `(?i)` makes the match case-insensitive; attackers use `-EnCoDeDcOmMaNd` precisely to defeat
  case-sensitive rules.
* Backslashes are escaped (`\\powershell\.exe`) because the value is a regex, and the leading
  `\\` anchors on the path separator so `notpowershell.exe` does not match.
* Level 10 (Medium): a hidden-window encoded command is strongly suspicious but occasionally
  produced by legitimate software installers.

```xml
<rule id="100112" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.parentImage">(?i)\\winword\.exe|\\excel\.exe|\\powerpnt\.exe|\\outlook\.exe|...</field>
  <field name="win.eventdata.image">(?i)\\powershell\.exe|\\cmd\.exe|\\wscript\.exe|...</field>
  <mitre><id>T1204.002</id><id>T1059.001</id></mitre>
</rule>
```

* This is a **parent–child relationship** rule, and it is the highest-fidelity phishing
  detection you can build from process telemetry alone. Office applications have no legitimate
  reason to launch a shell. Sysmon provides `parentImage`; native 4688 gives you far less.

```xml
<rule id="100113" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4104$</field>
  <field name="win.eventdata.scriptBlockText">(?i)downloadstring|downloadfile|invoke-webrequest|net\.webclient|iex |invoke-expression|frombase64string</field>
  <mitre><id>T1059.001</id><id>T1105</id></mitre>
</rule>
```

* Matches the **decoded** script text, so it still fires when the command line was Base64 —
  obfuscation at the command line does not help the attacker here.
* `iex ` with a trailing space reduces matches on unrelated words containing "iex".

```xml
<rule id="100115" level="13">
  <field name="win.eventdata.scriptBlockText">(?i)set-mppreference|add-mppreference -exclusionpath|disablerealtimemonitoring|clear-eventlog|wevtutil cl</field>
  <mitre><id>T1562.001</id><id>T1070.001</id></mitre>
</rule>
```

* Defence tampering. Level 13 because an attacker turning off Defender or clearing logs is a
  late-stage action — you are already behind.

---

## 4. Generating the telemetry in the lab (MANUAL STEP)

Use [`/scripts/Invoke-LabPowerShellActivity.ps1`](../scripts/Invoke-LabPowerShellActivity.ps1).
Every command it runs is harmless — it prints text, reads an environment variable and
optionally requests a file from a local lab web server. There is no payload and no external
network destination.

```powershell
# On WIN-SOC-EP01, normal (non-elevated) user context. LAB ONLY.
.\Invoke-LabPowerShellActivity.ps1 -Scenario All
```

Telemetry produced: Sysmon EID 1 (encoded / hidden-window command lines), PowerShell 4104
(decoded script blocks containing `IEX` and `Net.WebClient`), Sysmon EID 3 if the optional
local download step is used.

---

## 5. False positives

| Cause | Recognition | Handling |
|---|---|---|
| Software deployment tools (SCCM, Intune, Chocolatey, winget) run encoded/hidden PowerShell | Parent is the management agent; occurs on a schedule; identical command hash across hosts | Exclude by **parent image + user**, never by "contains powershell" |
| Legitimate admin scripts using `-ExecutionPolicy Bypass` | Run by a known admin account during working hours, script path on an internal share | Allowlist the specific script path/hash and record who approved it |
| Monitoring agents using `Invoke-WebRequest` to an internal endpoint | Destination is an internal management server, constant interval | Exclude by destination + process |
| IT automation creating scheduled tasks | Correlates with a change ticket | Verify the ticket, then close |

Tuning must always be **narrow**: exclude a specific parent image, script path or signed
publisher. Excluding "all encoded PowerShell from the Administrators group" deletes the
detection.

---

## 6. Investigation steps (SOC L1)

1. **Read the command line** in the alert (`data.win.eventdata.commandLine`). If it is
   Base64 (`-enc <string>`), decode it — this is safe, decoding is not executing:

   ```powershell
   # Safe: decodes only, does not run anything
   [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<BASE64>'))
   ```
   ```bash
   echo '<BASE64>' | base64 -d | iconv -f UTF-16LE -t UTF-8
   ```

2. **Get the decoded intent from 4104** — search
   `data.win.system.eventID:4104 AND agent.name:"WIN-SOC-EP01"` around the timestamp. This
   gives the real script, including any URL, file path or account name.
3. **Build the process tree.** Take `ProcessGuid` / `ParentProcessGuid` from the Sysmon event
   and walk upward: what launched PowerShell? `explorer.exe` (user double-clicked something)?
   `winword.exe` (document)? `services.exe` (a service)? A remote-execution parent such as
   `wmiprvse.exe` or `services.exe` means lateral movement.
4. **Check the user context** (`win.eventdata.user`) and integrity level. Did it run elevated?
5. **Look for network activity** — Sysmon EID 3 from the same `ProcessGuid`. Any destination
   IP or port? Then Sysmon EID 22 for the DNS name requested.
6. **Look for dropped files** — Sysmon EID 11 from the same process. Anything written to
   `%TEMP%`, `%APPDATA%` or `Users\Public`? Record path and SHA256.
7. **Look for persistence** created afterwards — registry Run keys (Sysmon EID 12/13),
   scheduled tasks (4698), services (7045), new accounts (4720).
8. **Ask the user.** "Did you run a script at 14:32?" resolves a large share of these alerts
   faster than any log query.
9. **Decide and document.**

**Wazuh Discover queries used**

```
rule.id:(100110 OR 100111 OR 100112 OR 100113 OR 100114 OR 100115)
data.win.system.eventID:4104 AND agent.name:"WIN-SOC-EP01"
data.win.eventdata.parentImage:*winword.exe
data.win.eventdata.commandLine:*EncodedCommand*
rule.mitre.id:"T1059.001"
```

---

## 7. Recommended response

| Verdict | Action |
|---|---|
| **False positive** | Identify the exact source (agent, script, publisher), add a narrow exclusion, document the tuning decision, close. |
| **True positive, no payload retrieved** (download failed / destination unreachable) | Capture IOCs (URL, IP, hash, script text), block the destination, scan the host, reset the user's password if credentials were touched, monitor 48 h. |
| **True positive, code executed** | **Escalate.** Isolate the host, preserve Sysmon + PowerShell logs, collect the dropped file hashes, hunt the IOCs across every other endpoint, rebuild if execution is confirmed. |

**Hardening recommendations produced by this detection**

* Enable **Script Block Logging** and **Module Logging** everywhere, and forward both.
* Enable PowerShell **Constrained Language Mode** for standard users where feasible.
* Remove Windows PowerShell v2 (`Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindows-PowerShellV2`) — v2 does not support script block logging and is used to downgrade-evade it.
* Block Office applications from creating child processes (Microsoft Defender ASR rule).
* Restrict who may run PowerShell interactively through AppLocker / WDAC.
