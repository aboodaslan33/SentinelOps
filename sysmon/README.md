# Sysmon — Configuration Guide

**File:** [`sysmon-config.xml`](sysmon-config.xml) · **Target:** Sysmon v15+ on Windows 10/11 · **Scope:** laboratory use

---

## 1. Why Sysmon at all?

Windows already logs process creation as **Event ID 4688**, so why add a third-party driver?

| Question a SOC analyst must answer | Native 4688 | Sysmon Event ID 1 |
|---|---|---|
| What process started? | Yes | Yes |
| What was the full command line? | Only if *"Include command line in process creation events"* is enabled | Always |
| What was the **parent** process image? | Parent process name only | Full parent image **and parent command line** |
| What is the file hash? | No | Yes (SHA256) |
| What is the integrity level? | No | Yes (tells you if it ran elevated) |
| Unique process GUID to link events together? | No | Yes (`ProcessGuid`) |
| Did the process make a network connection / DNS query? | No | Yes (Event ID 3 / 22) |

Sysmon gives the analyst the **process ancestry and command line** that turns "powershell.exe
ran" into "Word spawned powershell.exe with an encoded command" — which is the difference
between an unactionable log line and a real detection.

---

## 2. Installation (MANUAL STEP — run on the Windows endpoint)

```powershell
# Run PowerShell as Administrator on WIN-SOC-EP01

# 1. Download Sysmon from Microsoft Sysinternals (official source only)
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Lab\Sysmon.zip"

# 2. Extract
Expand-Archive -Path "C:\Lab\Sysmon.zip" -DestinationPath "C:\Lab\Sysmon" -Force

# 3. Copy this repository's config next to the binary
Copy-Item .\sysmon-config.xml "C:\Lab\Sysmon\sysmon-config.xml"

# 4. Install the driver with the configuration
C:\Lab\Sysmon\Sysmon64.exe -accepteula -i C:\Lab\Sysmon\sysmon-config.xml
```

**Expected output**

```
System Monitor v15.x - System activity monitor
...
Sysmon64 installed.
SysmonDrv installed.
Starting SysmonDrv.
SysmonDrv started.
Starting Sysmon64..
Sysmon64 started.
```

**Verification**

```powershell
Get-Service Sysmon64                                   # Status must be Running
C:\Lab\Sysmon\Sysmon64.exe -c                          # Prints the ACTIVE configuration
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
    Format-Table TimeCreated, Id, Message -AutoSize
```

Event ID **4** ("Sysmon service state changed") should be the first event in the log.

**Updating the config after an edit**

```powershell
C:\Lab\Sysmon\Sysmon64.exe -c C:\Lab\Sysmon\sysmon-config.xml
```

**Uninstalling**

```powershell
C:\Lab\Sysmon\Sysmon64.exe -u force
```

---

## 3. Section-by-section explanation

### `<Sysmon schemaversion="4.90">`
The schema version must be supported by the installed binary. Check the supported value with
`Sysmon64.exe -? config`. If your build reports a different version, change this attribute —
a mismatch makes Sysmon refuse the file.

### `<HashAlgorithms>SHA256</HashAlgorithms>`
One hash algorithm keeps each event small. SHA256 is the algorithm accepted by VirusTotal,
MISP and most threat-intel feeds. Using `*` would add MD5/SHA1/IMPHASH and roughly double the
size of every process event for little analytical gain in a lab.

### `<DnsLookup>False</DnsLookup>`
Stops Sysmon from performing reverse DNS on every network connection. This avoids added
latency and — importantly in a lab — avoids Sysmon generating its own DNS traffic that would
then appear in the telemetry it is supposed to be observing.

### Include vs exclude — the core filtering decision

| Block style | Meaning | Used here for |
|---|---|---|
| `onmatch="include"` with rules | Log **only** events matching the rules | Network, FileCreate, DNS, Registry, Pipes, ProcessAccess |
| `onmatch="exclude"` with rules | Log **everything except** matching events | ProcessCreate, ProcessTerminate, DriverLoad, WMI, Tampering |
| `onmatch="include"` **empty** | Log **nothing** — the documented way to disable an event type | ImageLoad, RawAccessRead, ClipboardChange |

> Common beginner error: leaving an event type out of the file entirely does **not** disable
> it. Add an empty `<EventType onmatch="include" />` block instead.

### Event ID 1 — Process creation (exclude model)
Everything is logged, minus a short list of predictable Windows noise (`SearchIndexer`,
`RuntimeBroker`, `CompatTelRunner`, Windows Update workers) and the lab's own agents
(`Sysmon64.exe`, `wazuh-agent.exe`) to prevent self-referential loops.

On a single idle workstation this produces roughly a few hundred events per hour — completely
manageable — while guaranteeing that **no attacker-launched process is silently missed**. On a
busy server you would invert this to an include model.

### Event ID 3 — Network connection (include model)
Logging every TCP connection on a workstation is unusable. This config logs a connection only
when it is interesting:

* the process is an **interpreter or shell** (`powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe`);
* the process is a **LOLBin download tool** (`certutil.exe`, `bitsadmin.exe`, `curl.exe`, `rundll32.exe`, `regsvr32.exe`);
* the process runs from a **user-writable staging directory** (`\AppData\Local\Temp\`, `\Users\Public\`, `\Downloads\`);
* the destination port is a **remote-administration port** (445, 3389, 5985/5986) or 4444, the
  historical default listener port of common offensive frameworks.

### Event ID 5 — Process terminated
Same exclusions as Event ID 1. Termination events cost almost nothing and let the analyst
state *how long* a process lived — a short-lived `powershell.exe` that ran for 900 ms behaves
very differently from one that ran for two hours.

### Event ID 6 — Driver loaded
Microsoft-signed drivers are excluded; everything else is logged. A new unsigned driver on a
workstation is a strong rootkit / vulnerable-driver indicator.

### Event ID 8 — CreateRemoteThread
A thread created by one process inside another is the classic code-injection primitive. Volume
is tiny, so everything except two well-known benign sources is logged.

### Event ID 10 — Process access (LSASS only)
This is the highest-noise Sysmon event if left open, so it is scoped to a single target:
`lsass.exe`. Any handle opened against LSASS by an unexpected process is the core telemetry for
credential dumping (MITRE **T1003.001**). Trusted callers (WMI provider, Defender) are excluded.

### Event ID 11 — File create (include model)
Targets *where* attackers write and *what* they write:
staging directories (`Temp`, `AppData\Roaming`, `Users\Public`, `Downloads`, `Windows\Temp`),
autostart locations (`Startup` folder, `System32\Tasks`), and executable/script extensions
(`.exe .dll .ps1 .bat .cmd .vbs .js .hta .lnk .scr`). A second exclude group removes Windows
Update / Defender / WinSxS servicing noise.

### Event ID 12/13/14 — Registry (include model)
Scoped to persistence and defence-evasion keys only: `Run`, `RunOnce`, `Startup`,
`CurrentControlSet\Services\`, `Image File Execution Options\`, `Winlogon\Shell`,
`Winlogon\Userinit`, and Windows Defender exclusion/disable keys (MITRE **T1562.001**).

### Event ID 15 — File create stream hash
Records Alternate Data Streams, including `Zone.Identifier` — the **Mark-of-the-Web**. This is
how an analyst proves a file was downloaded from the internet rather than created locally.

### Event ID 17/18 — Named pipes
A short list of pipes used by remote-execution tooling (`PSEXESVC`, `paexec`, `remcom`) and by
remote service/task control (`svcctl`, `atsvc`, `winreg`). Excellent lateral-movement signal at
near-zero volume.

### Event ID 19/20/21 — WMI event subscription
Logged in full. Permanent WMI event subscriptions are almost never created legitimately on a
workstation and are a well-known stealth persistence technique.

### Event ID 22 — DNS query (include model)
Filtered **by process**, not by domain: we want to know when `powershell.exe` or `certutil.exe`
resolves a name. The browser's DNS history is deliberately not collected — it is high volume and
low value in this lab.

### Event ID 23/26 — File delete (detected only)
`FileDeleteDetected` records the deletion **without archiving a copy of the file**.
`ArchiveDirectory` is intentionally not configured: file archiving fills the disk quickly and
can capture sensitive user documents. Scoped to executables and scripts in staging paths, this
catches anti-forensic clean-up (MITRE **T1070.004**).

### Disabled on purpose
`ImageLoad` (thousands of events per minute), `RawAccessRead` (backup/AV noise) and
`ClipboardChange` (privacy sensitive, not needed here).

---

## 4. Tuning checklist after deployment

1. Run the lab for 24 hours with no attack simulation.
2. Count events per type:

   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20000 |
       Group-Object Id | Sort-Object Count -Descending |
       Format-Table Count, Name -AutoSize
   ```

3. For any event type above roughly 10 % of total volume, identify the top producing process:

   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20000 |
       Where-Object Id -eq 11 |
       ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data |
           Where-Object Name -eq 'Image' | Select-Object -Expand '#text' } |
       Group-Object | Sort-Object Count -Descending | Select-Object -First 10
   ```

4. Add a **narrow** exclusion (full path + specific directory), never a broad one.
   `<Image condition="contains">chrome</Image>` is a bad exclusion — an attacker can name their
   binary `chrome_update.exe`.
5. Re-apply with `Sysmon64.exe -c sysmon-config.xml` and re-verify.

---

## 5. Log size

Increase the Sysmon channel size so events survive long enough to be collected and investigated:

```powershell
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:1073741824   # 1 GB
wevtutil gl "Microsoft-Windows-Sysmon/Operational"                  # verify maxSize
```

---

## 6. Credit

The filtering approach in this file is informed by the publicly available community
configurations from SwiftOnSecurity and Olaf Hartong, simplified and re-commented for a
single-endpoint SOC lab. It is deliberately smaller and easier to read than those production
configurations so that every rule can be explained in an interview.
