# Detection 04 — Suspicious Process Execution

> Laboratory detection. All processes referenced are standard Windows binaries executed with
> benign arguments inside the isolated SentinelOps lab.

| Field | Value |
|---|---|
| **Detection name** | Suspicious Process Execution / Host Reconnaissance |
| **Detection ID** | SO-DET-004 |
| **Wazuh rules** | `100130`, `100131`, `100132`, `100133`, `100134` |
| **Data source** | Sysmon Operational log (primary), Windows Security log (fallback) |
| **Windows Event ID** | `4688` — process creation (requires *"Include command line in process creation events"*) |
| **Sysmon Event IDs** | `1` (process creation), `3` (network connection), `11` (file created), `22` (DNS query), `5` (process terminated) |
| **Severity** | Informational 3 (single discovery command) → **Medium 10** (execution from a staging directory) → **High 12–13** (recon burst, LOLBin download, masquerading) |
| **MITRE ATT&CK** | **TA0007 Discovery** — [T1082](https://attack.mitre.org/techniques/T1082/) System Information Discovery, [T1087.001](https://attack.mitre.org/techniques/T1087/001/) Account Discovery: Local Account, [T1033](https://attack.mitre.org/techniques/T1033/) System Owner/User Discovery, [T1016](https://attack.mitre.org/techniques/T1016/) System Network Configuration Discovery; **TA0005 Defense Evasion** — [T1218](https://attack.mitre.org/techniques/T1218/) System Binary Proxy Execution, [T1036.003](https://attack.mitre.org/techniques/T1036/003/) Rename System Utility; **TA0011** — [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer |

---

## 1. Description

"Suspicious process" is not a property of a binary — `whoami.exe` is a Microsoft-signed tool
that thousands of legitimate scripts run every day. Suspicion comes from **context**:

| Context question | Benign answer | Suspicious answer |
|---|---|---|
| **Who is the parent?** | `explorer.exe`, `services.exe`, an installer | `winword.exe`, `mshta.exe`, `wmiprvse.exe` |
| **Where does the image live?** | `C:\Windows\System32\`, `C:\Program Files\` | `%TEMP%`, `\Users\Public\`, `\Downloads\` |
| **What are the arguments?** | `ipconfig /all` once | `certutil -urlcache -f http://... file.exe` |
| **Which user?** | The logged-on user, during their shift | `SYSTEM` at 03:00, or a service account running interactive tools |
| **How many, how fast?** | One command | Six different discovery commands in 40 seconds |
| **Does the name match the binary?** | `powershell.exe` with OriginalFileName `PowerShell.EXE` | `svchost32.exe` with OriginalFileName `PowerShell.EXE` |

This detection therefore looks at **rate, path, arguments, parentage and name integrity**, not
at the binary alone.

### The reconnaissance burst

After gaining execution, an attacker almost always orients themselves first. On Windows that
looks like:

```
whoami /all              -> who am I, what privileges do I hold   (T1033)
hostname / systeminfo    -> what is this machine                  (T1082)
ipconfig /all            -> what network am I on                  (T1016)
net user / net localgroup administrators -> which accounts exist  (T1087.001)
net view / arp -a        -> what else can I reach                 (T1018/T1016)
tasklist                 -> what security tooling is running      (T1057/T1518.001)
```

Individually: normal admin commands. **Six of them from one shell inside a minute: that is a
human or a script orienting itself**, and that is what rule `100131` detects.

---

## 2. Key fields

| Field | Wazuh field name | Use in triage |
|---|---|---|
| Process image | `win.eventdata.image` | What ran, and from where |
| Command line | `win.eventdata.commandLine` | Intent — the most valuable single field |
| Parent image | `win.eventdata.parentImage` | Execution chain |
| Parent command line | `win.eventdata.parentCommandLine` | How the parent itself was launched |
| User | `win.eventdata.user` | Context and blast radius |
| Integrity level | `win.eventdata.integrityLevel` | `High`/`System` means it ran elevated |
| Hashes | `win.eventdata.hashes` | IOC lookup, reputation |
| Original file name | `win.eventdata.originalFileName` | Detects renamed binaries |
| Process GUID | `win.eventdata.processGuid` | Joins EID 1 / 3 / 11 / 22 / 5 into one story |
| Current directory | `win.eventdata.currentDirectory` | Where the actor is working |
| Host / time | `win.system.computer`, `win.system.systemTime` | Scope and timeline |

`4688` vs Sysmon `1`: 4688 is a useful fallback if Sysmon is missing or was tampered with, but
it gives no hashes, no original file name, no parent command line and no process GUID. **Use
Sysmon as primary and 4688 as corroboration** — including corroboration that Sysmon itself was
not stopped (rule `100152`).

---

## 3. Wazuh rules, explained

```xml
<rule id="100130" level="3">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image">(?i)\\whoami\.exe|\\systeminfo\.exe|\\ipconfig\.exe|\\net\.exe|\\net1\.exe|\\nltest\.exe|\\quser\.exe|\\tasklist\.exe|\\arp\.exe|\\route\.exe|\\netstat\.exe</field>
  <mitre><id>T1082</id></mitre>
</rule>
```

* Level 3 = informational. Alerting on every `whoami` would train the analyst to ignore the
  detection. Its job is to feed the correlation rule below.
* `net1.exe` is included because `net.exe` silently hands most subcommands to `net1.exe`;
  a rule that only watches `net.exe` misses half the evidence.

```xml
<rule id="100131" level="12" frequency="5" timeframe="60">
  <if_matched_sid>100130</if_matched_sid>
  <same_field>win.system.computer</same_field>
  <different_field>win.eventdata.image</different_field>
  <mitre><id>T1082</id><id>T1087.001</id><id>T1033</id><id>T1016</id></mitre>
</rule>
```

* `same_field` (one host) + `different_field` (five **distinct** binaries) is what separates
  reconnaissance from a monitoring script that runs `ipconfig` in a loop. Without
  `different_field`, one repetitive scheduled task would generate this alert every hour.

```xml
<rule id="100132" level="13">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.commandLine">(?i)certutil(\.exe)?.{0,80}(-urlcache|-decode|-encode)|bitsadmin(\.exe)?.{0,80}/transfer|mshta(\.exe)?.{0,80}(http|javascript:|vbscript:)|regsvr32(\.exe)?.{0,80}(/i:http|scrobj\.dll)|rundll32(\.exe)?.{0,80}(javascript:|http)</field>
  <mitre><id>T1218</id><id>T1105</id></mitre>
</rule>
```

* **Living-off-the-land binaries (LOLBins).** These are signed Microsoft tools misused as
  downloaders and script hosts. Each alternative pairs a binary with the argument that makes
  it dangerous — matching on `certutil.exe` alone would be a false-positive factory, because
  certutil has a legitimate certificate-management job.
* `.{0,80}` allows other switches between the binary and the dangerous argument while keeping
  the regex bounded (an unbounded `.*` is slow and can match across unrelated text).

```xml
<rule id="100133" level="10">
  <field name="win.eventdata.image">(?i)\\AppData\\Local\\Temp\\|\\Users\\Public\\|\\Downloads\\|C:\\Windows\\Temp\\|\\AppData\\Roaming\\</field>
  <mitre><id>T1204.002</id></mitre>
</rule>
```

* Execution from a user-writable staging directory. Kept at Medium because legitimate
  installers genuinely unpack and run from `%TEMP%`. This is a **pivot, not a verdict** —
  it tells the analyst where to look, not what happened.

```xml
<rule id="100134" level="12">
  <field name="win.eventdata.originalFileName">(?i)^(powershell\.exe|cmd\.exe|psexec\.c|mimikatz\.exe|procdump)</field>
  <field name="win.eventdata.image" negate="yes">(?i)\\powershell\.exe|\\cmd\.exe|\\psexec(64)?\.exe|\\procdump(64)?\.exe</field>
  <mitre><id>T1036.003</id></mitre>
</rule>
```

* **Masquerading detection.** `OriginalFileName` comes from the PE version resource inside the
  file and does not change when the file is renamed on disk. If the on-disk name disagrees
  with it, someone renamed the binary — a deliberate evasion step. `negate="yes"` expresses
  "image is **not** the expected name".
* This detection is **only possible with Sysmon**; native 4688 does not carry the field.

---

## 4. Generating the telemetry in the lab (MANUAL STEP)

Use [`/scripts/Invoke-LabSuspiciousProcess.ps1`](../scripts/Invoke-LabSuspiciousProcess.ps1).
It runs read-only discovery commands and a copied-and-renamed **copy of a harmless Windows
binary** to demonstrate the masquerading detection. It changes nothing on the system and
cleans up after itself.

```powershell
# On WIN-SOC-EP01. LAB ONLY.
.\Invoke-LabSuspiciousProcess.ps1 -Scenario Recon
.\Invoke-LabSuspiciousProcess.ps1 -Scenario StagingDirectory
```

---

## 5. False positives

| Cause | Recognition | Handling |
|---|---|---|
| Login scripts / GPO scripts running `net use`, `ipconfig` | Fire at logon, parent is `userinit.exe` or `gpscript.exe`, same commands every time | Exclude by **parent process + user + exact command line** |
| Monitoring or inventory agents running `systeminfo`, `tasklist` | Fixed interval, parent is the agent, runs as SYSTEM | Exclude by parent image path |
| Helpdesk troubleshooting | Known admin, business hours, correlates with a ticket, commands typed with human timing and typos | Confirm with the technician, close |
| Installers unpacking to `%TEMP%` | Signed binary, parent is `msiexec.exe`/browser, single burst during a known install | Verify the signature and hash, close |
| Software updaters using `certutil` for certificate work (no `-urlcache`) | Argument set is genuinely certificate-related | Rule already excludes this by requiring the dangerous switch |

---

## 6. How the analyst decides legitimate vs suspicious

Work the questions in this order — stop as soon as you have a defensible answer:

1. **Parent process.** Is the chain plausible? `explorer.exe → cmd.exe → whoami.exe` after a
   user opened a terminal is normal. `winword.exe → cmd.exe → whoami.exe` is not.
2. **Image path.** `C:\Windows\System32\whoami.exe` is the real tool.
   `C:\Users\Public\whoami.exe` is not the real tool, even if it behaves like it.
3. **Signature and hash.** Check `win.eventdata.hashes`. Look the SHA256 up in your threat-intel
   source. Unsigned binary in a user directory = strong signal.
4. **Command line.** Does it read like a human administrator or like automation? Arguments such
   as `-urlcache -f http://...` have no administrative use case.
5. **User and integrity level.** Did a standard user's process run at `High` integrity? How?
6. **Timing.** Working hours vs 03:00. Correlate with the user's own logon session (4624) — was
   the user even present?
7. **Sequence.** Look 10 minutes either side of the event. One `whoami` is nothing; `whoami` →
   `net localgroup administrators` → `net user backup /add` is an intrusion.
8. **Ask the user or the admin.** Fastest disambiguation available.

**Wazuh Discover queries used**

```
rule.id:(100130 OR 100131 OR 100132 OR 100133 OR 100134)
data.win.eventdata.parentImage:*cmd.exe AND agent.name:"WIN-SOC-EP01"
data.win.eventdata.image:*\\Temp\\*
data.win.eventdata.commandLine:*certutil*
data.win.eventdata.processGuid:"{a1b2c3d4-...}"     # pivot to EID 3 / 11 / 22 / 5
```

---

## 7. Recommended response

| Verdict | Action |
|---|---|
| **False positive** | Identify the exact automation, exclude by parent + command line, document, close. |
| **True positive, reconnaissance only** | Capture the full process tree, identify the initial access vector, reset credentials used in that session, monitor the host closely for 72 h, raise the alert to L2 with the timeline. |
| **True positive with download / execution** | **Escalate and contain.** Isolate the host from the network, preserve Sysmon + Security logs, collect file hashes and destination IPs/domains as IOCs, sweep the environment for the same hashes, plan rebuild. |

**Hardening recommendations produced by this detection**

* Enable **command line auditing** for 4688 so the fallback source is actually useful.
* Deploy **AppLocker / WDAC** to block execution from `%TEMP%`, `%APPDATA%` and `Users\Public`.
* Enable Microsoft Defender **ASR rules**: block executable content from email/webmail, block
  Office child processes, block obfuscated scripts.
* Restrict local administrator rights for standard users.
