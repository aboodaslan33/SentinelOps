# SentinelOps — Lab Installation Guide

> **Safety statement.** Every instruction in this guide applies to virtual machines you own,
> on an isolated host-only network. Nothing here should be executed against a production
> system, a machine you do not own, or any host reachable from the internet.

**Estimated time:** 3–4 hours for a first build.
**Prerequisites:** a host with 16 GB RAM (8 GB workable), 150 GB free disk, virtualisation
enabled in BIOS, and a working hypervisor (VirtualBox or VMware Workstation Player — both free).

---

## Table of contents

1. [Lab topology and VM requirements](#1-lab-topology-and-vm-requirements)
2. [Network configuration](#2-network-configuration)
3. [Wazuh manager installation (Ubuntu)](#3-wazuh-manager-installation-ubuntu)
4. [First login to the Wazuh Dashboard](#4-first-login-to-the-wazuh-dashboard)
5. [Wazuh agent installation (Windows)](#5-wazuh-agent-installation-windows)
6. [Windows audit policy configuration](#6-windows-audit-policy-configuration)
7. [PowerShell logging configuration](#7-powershell-logging-configuration)
8. [Sysmon installation](#8-sysmon-installation)
9. [Telling the agent which logs to collect](#9-telling-the-agent-which-logs-to-collect)
10. [Deploying the SentinelOps detection rules](#10-deploying-the-sentinelops-detection-rules)
11. [End-to-end verification](#11-end-to-end-verification)
12. [Troubleshooting](#12-troubleshooting)
13. [Snapshot and reset procedure](#13-snapshot-and-reset-procedure)

---

## 1. Lab topology and VM requirements

| VM | Role | OS | vCPU | RAM | Disk | IP |
|----|------|----|------|-----|------|----|
| `wazuh-mgr` | SIEM (manager + indexer + dashboard) | Ubuntu Server 22.04 LTS | 2 | 4 GB min / 8 GB recommended | 50 GB | `192.168.56.10` |
| `WIN-SOC-EP01` | Monitored endpoint | Windows 11 Pro (or Windows 10 Pro) | 2 | 4 GB | 60 GB | `192.168.56.20` |
| `LAB-ATTACK01` | Attack simulator (**optional**) | Windows 10 Pro or Kali Linux | 1 | 2 GB | 40 GB | `192.168.56.30` |

**Windows licensing note (MANUAL STEP):** Microsoft publishes free, time-limited evaluation
VMs for testing at the *Microsoft Edge / Windows developer virtual machines* download page, and
Windows Server / Windows Enterprise evaluation ISOs on the Microsoft Evaluation Center. Use one
of those, or a licence you own. Do not use an unlicensed installation.

> With only 8 GB of host RAM: build `wazuh-mgr` (4 GB) and `WIN-SOC-EP01` (3 GB), skip
> `LAB-ATTACK01`, and run the brute-force simulation locally. The alert then shows
> `127.0.0.1`/`::1` as the source instead of a remote IP — note that in your incident report.

---

## 2. Network configuration

**Where:** hypervisor settings, before powering on any VM.

### VirtualBox

1. **File → Tools → Network Manager → Host-only Networks → Create.**
   Confirm the adapter address is `192.168.56.1/24` and **disable its DHCP server** (we use
   static IPs so the lab is deterministic).
2. For each VM: **Settings → Network**
   * **Adapter 1:** Host-only Adapter → `vboxnet0`  ← always enabled
   * **Adapter 2:** NAT  ← enable **only** while downloading software, then disable

### VMware Workstation Player

Use **Host-only** for Adapter 1 and **NAT** for the temporary second adapter; the host-only
subnet is configurable under *Edit → Virtual Network Editor*.

### Static IP — Ubuntu (`wazuh-mgr`)

```bash
# Where: on the Ubuntu VM console, as root/sudo
sudo nano /etc/netplan/00-installer-config.yaml
```

```yaml
network:
  version: 2
  ethernets:
    enp0s3:                      # check the real name with: ip -br a
      addresses: [192.168.56.10/24]
      nameservers:
        addresses: [1.1.1.1]
```

```bash
sudo netplan apply
ip -br a                         # expect: enp0s3  UP  192.168.56.10/24
```

### Static IP — Windows (`WIN-SOC-EP01`)

```powershell
# Where: elevated PowerShell on the Windows VM
Get-NetAdapter                                    # note the InterfaceIndex of the host-only NIC
New-NetIPAddress -InterfaceIndex 5 -IPAddress 192.168.56.20 -PrefixLength 24
Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, IPAddress
```

### Verify connectivity both ways

```powershell
# From Windows
Test-NetConnection 192.168.56.10 -Port 1514       # TcpTestSucceeded must be True (after §3)
ping 192.168.56.10
```

```bash
# From Ubuntu
ping -c 3 192.168.56.20
```

> **Common error:** ping fails from Ubuntu to Windows. This is usually the **Windows Firewall
> blocking ICMP**, not a network fault — the Wazuh agent will still connect fine. To confirm the
> path, use `Test-NetConnection` from Windows instead.

---

## 3. Wazuh manager installation (Ubuntu)

**Where:** on `wazuh-mgr`, with the temporary NAT adapter enabled (internet needed once).

### 3.1 Prepare

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl gnupg apt-transport-https lsb-release
sudo timedatectl set-timezone UTC          # UTC everywhere avoids timeline confusion
timedatectl                                # verify "Time zone: UTC"
free -h                                    # confirm >= 4 GB RAM
df -h /                                    # confirm >= 30 GB free
```

> **Why UTC?** Every timestamp in every incident report in this repository is UTC. Mixed
> time zones between the endpoint, the manager and the dashboard is the single most common
> cause of "the events are not arriving" — when in fact they arrived with a different
> timestamp than the one you were looking at.

### 3.2 Install with the official assistant

The **Wazuh installation assistant** installs the currently supported 4.x release of all three
components (manager, indexer, dashboard) in an all-in-one deployment. Using the assistant rather
than pinning a version in this document means the lab stays reproducible as Wazuh releases
updates.

```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

**Expected output (the final lines are the ones that matter):**

```
INFO: --- Summary ---
INFO: You can access the web interface https://<wazuh-dashboard-ip>
    User: admin
    Password: <a long random password>
INFO: Installation finished.
```

> **CRITICAL — do not commit this password to GitHub.** Store it in your own password manager.
> The installer also writes `wazuh-install-files.tar`, which contains certificates and
> passwords. It is already listed in this repository's `.gitignore`. Keep it on the VM only.
>
> Recover the password later with:
> ```bash
> sudo tar -xf wazuh-install-files.tar -O wazuh-install-files/wazuh-passwords.txt | head -20
> ```

### 3.3 Verify the installation

```bash
sudo systemctl status wazuh-manager  --no-pager
sudo systemctl status wazuh-indexer  --no-pager
sudo systemctl status wazuh-dashboard --no-pager
sudo /var/ossec/bin/wazuh-control info      # prints the installed version - RECORD THIS
sudo /var/ossec/bin/wazuh-control status    # every daemon should say "is running"
```

**Expected:** `wazuh-modulesd`, `wazuh-monitord`, `wazuh-logcollector`, `wazuh-remoted`,
`wazuh-syscheckd`, `wazuh-analysisd`, `wazuh-maild` (optional), `wazuh-execd`, `wazuh-db`,
`wazuh-authd` all reported as running.

```bash
sudo ss -lntp | grep -E '1514|1515|55000|9200|443'
```

**Expected:** listeners on `1514` (agent traffic), `1515` (enrolment), `55000` (API),
`9200` (indexer), `443` (dashboard).

### 3.4 Disable the temporary NAT adapter

Once installation is complete, **power off the VM and disable the NAT adapter** in the
hypervisor. The lab is now isolated.

---

## 4. First login to the Wazuh Dashboard

**Where:** a browser on your host machine.

1. Open `https://192.168.56.10`.
2. Accept the self-signed certificate warning (expected — the installer generates its own CA).
3. Log in as `admin` with the password from §3.2.
4. Change the password immediately:
   *Dashboard → ☰ menu → Indexer management → Security → Internal users → admin → Edit.*

**Common errors**

| Symptom | Cause | Fix |
|---|---|---|
| Browser cannot reach the page | Host-only adapter not attached, or wrong IP | `ip -br a` on the manager; ping from the host |
| "Wazuh dashboard server is not ready yet" | Indexer still starting (can take 2–5 minutes on 4 GB) | Wait, then `sudo systemctl restart wazuh-dashboard` |
| Login rejected | Password copied with a trailing space | Re-read it with the `tar -xf` command in §3.2 |
| Dashboard loads but shows no data | No agents enrolled yet | Continue to §5 |

---

## 5. Wazuh agent installation (Windows)

**Where:** on `WIN-SOC-EP01`, in an **elevated** PowerShell window.

### 5.1 Get the correct installer

**MANUAL STEP.** Download the Windows agent MSI matching your manager version from the official
Wazuh packages site (`https://packages.wazuh.com/4.x/windows/`). The agent version should match
the manager version you recorded in §3.3 — a newer agent than the manager is not supported.

Transfer it to the VM through a shared folder, or temporarily enable the NAT adapter.

### 5.2 Install and enrol in one command

```powershell
# Where: elevated PowerShell on WIN-SOC-EP01
# WAZUH_MANAGER  = manager IP
# WAZUH_AGENT_NAME = the name that will appear in the dashboard
msiexec.exe /i C:\Lab\wazuh-agent.msi /q `
    WAZUH_MANAGER="192.168.56.10" `
    WAZUH_AGENT_NAME="WIN-SOC-EP01" `
    WAZUH_REGISTRATION_SERVER="192.168.56.10"
```

**Expected:** the command returns without output; `C:\Program Files (x86)\ossec-agent\` now
exists.

### 5.3 Start the agent

```powershell
NET START WazuhSvc
Get-Service WazuhSvc                     # Status must be Running
```

### 5.4 Verify enrolment — from the endpoint

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 30
```

**Expected (the three lines that confirm success):**

```
INFO: Requesting a key from server: 192.168.56.10
INFO: Valid key received
INFO: (4102): Connected to the server (192.168.56.10:1514/tcp)
```

### 5.5 Verify enrolment — from the manager

```bash
sudo /var/ossec/bin/agent_control -l
```

**Expected:**

```
ID: 001, Name: WIN-SOC-EP01, IP: any, Active
```

Also visible at *Dashboard → Agents* with status **Active** (green).

### 5.6 Common agent errors

| Symptom in `ossec.log` | Cause | Fix |
|---|---|---|
| `ERROR: (1216): Unable to connect to '192.168.56.10:1514'` | Firewall, wrong IP, or manager not running | `Test-NetConnection 192.168.56.10 -Port 1514`; check `sudo ss -lntp \| grep 1514` |
| `ERROR: (4101): Unable to verify server certificate` | Certificate mismatch after a manager rebuild | Re-enrol: uninstall the agent, delete `C:\Program Files (x86)\ossec-agent\client.keys`, reinstall |
| `WARNING: (4111): Duplicated ID` / agent shows **Never connected** | The agent name already exists on the manager | `sudo /var/ossec/bin/manage_agents -r <id>` then re-enrol |
| Agent flaps between Active and Disconnected | VM clock drift between manager and endpoint | Set both to UTC and enable time sync (`w32tm /resync` on Windows) |
| Service will not start | Corrupt install | Uninstall via *Apps & features*, delete the `ossec-agent` folder, reinstall |

> **Agent status meanings:** *Active* = heartbeat within the keep-alive window.
> *Disconnected* = was enrolled, stopped reporting. *Never connected* = enrolled but the
> service never checked in (almost always a firewall or a key problem).

---

## 6. Windows audit policy configuration

**Where:** elevated PowerShell / `gpedit.msc` on `WIN-SOC-EP01`.
**Why:** Windows does **not** log failed logons, account creation or process creation by
default. Without this step the SIEM has nothing to detect and you will chase a "Wazuh problem"
that is really a Windows configuration problem.

### 6.1 Enable the subcategories (exact commands)

```powershell
# Where: elevated PowerShell on WIN-SOC-EP01

# Authentication - Scenario 1
auditpol /set /subcategory:"Logon"                     /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout"           /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation"     /success:enable /failure:enable

# Account and group management - Scenarios 3 and 5
auditpol /set /subcategory:"User Account Management"    /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management"  /success:enable /failure:enable

# Process execution - Scenarios 2, 4 and 5
auditpol /set /subcategory:"Process Creation"           /success:enable /failure:enable

# Privilege use and persistence - Scenario 5
auditpol /set /subcategory:"Sensitive Privilege Use"    /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change"        /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension"  /success:enable /failure:enable
```

> `"Other Object Access Events"` is what produces **4698** (scheduled task created).
> `"Security System Extension"` produces **4697** (service installed).

### 6.2 Include the command line in 4688

Process creation events are nearly useless without arguments:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

### 6.3 Set a lockout policy (so 4740 can fire)

```powershell
net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15
net accounts                       # verify the values
```

### 6.4 Increase the Security log size

```powershell
wevtutil sl Security /ms:1073741824     # 1 GB
wevtutil gl Security                    # verify maxSize
```

### 6.5 Verification

```powershell
auditpol /get /category:* | Select-String -Pattern "Logon|Process Creation|User Account|Security Group|Sensitive"
```

**Expected:** each listed subcategory shows `Success and Failure`.

**Functional test — generate one failed logon and confirm Windows recorded it:**

```powershell
# This deliberately fails. It is a local lab test only.
net use \\127.0.0.1\IPC$ /user:nosuchuser WrongPassword123!
# Expect: "System error 1326 ... The user name or password is incorrect."

Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 1 |
    Format-List TimeCreated, Id, Message
```

**Expected:** a 4625 event dated seconds ago. If nothing appears, the audit policy did not
apply — re-run §6.1 from an **elevated** prompt and check that no domain GPO is overriding it
(`gpresult /h C:\Lab\gp.html`).

---

## 7. PowerShell logging configuration

**Where:** elevated PowerShell on `WIN-SOC-EP01`. **This is the highest-value setting in the
entire lab** — it produces Event ID 4104 with the **de-obfuscated** script text.

```powershell
# Script Block Logging (Event ID 4104)
$sb = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $sb -Force | Out-Null
Set-ItemProperty -Path $sb -Name EnableScriptBlockLogging -Value 1 -Type DWord

# Module Logging (Event ID 4103)
$ml = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $ml -Force | Out-Null
Set-ItemProperty -Path $ml -Name EnableModuleLogging -Value 1 -Type DWord
New-Item -Path "$ml\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$ml\ModuleNames" -Name "*" -Value "*"

# Transcription (optional - writes a plain text transcript of every session)
$tr = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
New-Item -Path $tr -Force | Out-Null
Set-ItemProperty -Path $tr -Name EnableTranscripting     -Value 1 -Type DWord
Set-ItemProperty -Path $tr -Name OutputDirectory         -Value "C:\Lab\PSTranscripts"
Set-ItemProperty -Path $tr -Name EnableInvocationHeader  -Value 1 -Type DWord

# Remove PowerShell v2, which does not support script block logging and is used to evade it
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
```

**Verification**

```powershell
# Close and reopen PowerShell first, then run any command and check for 4104
Write-Host "SentinelOps logging test"
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 5 |
    Where-Object Id -eq 4104 | Format-List TimeCreated, Id, Message
```

**Expected:** a 4104 event whose message contains `Write-Host "SentinelOps logging test"`.

**Common error:** no 4104 events appear. Script block logging only applies to PowerShell
sessions started **after** the registry change — open a new window.

---

## 8. Sysmon installation

**MANUAL STEP.** Full instructions, expected output and tuning guidance are in
[`/sysmon/README.md`](../sysmon/README.md). Summary:

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Lab\Sysmon.zip"
Expand-Archive C:\Lab\Sysmon.zip -DestinationPath C:\Lab\Sysmon -Force
Copy-Item .\sysmon\sysmon-config.xml C:\Lab\Sysmon\
C:\Lab\Sysmon\Sysmon64.exe -accepteula -i C:\Lab\Sysmon\sysmon-config.xml

Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:1073741824
```

---

## 9. Telling the agent which logs to collect

**Where:** `C:\Program Files (x86)\ossec-agent\ossec.conf` on `WIN-SOC-EP01`, elevated editor.

The default agent config collects Application, Security and System. Add the Sysmon and
PowerShell channels. Place these blocks inside `<ossec_config>`:

```xml
  <!-- Windows Security log: authentication, accounts, process creation -->
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- System log: service installation (7045) -->
  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Sysmon: process creation, network, file, DNS -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- PowerShell script block logging (4104) and module logging (4103) -->
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Legacy PowerShell engine events (400/403/600) -->
  <localfile>
    <location>Windows PowerShell</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Task Scheduler operational log - useful corroboration for T1053.005 -->
  <localfile>
    <location>Microsoft-Windows-TaskScheduler/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
```

Optional — filter at the agent to reduce volume (advanced, use only after baselining):

```xml
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID != 5145 and EventID != 5156 and EventID != 4658]</query>
  </localfile>
```

Restart the agent:

```powershell
Restart-Service WazuhSvc
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20
```

**Expected:** lines reading
`INFO: (1951): Analyzing event log: 'Microsoft-Windows-Sysmon/Operational'` for each channel.

**Common error:** `ERROR: (1103): Could not open file ... 'Microsoft-Windows-Sysmon/Operational'`
means Sysmon is not installed or the channel name is misspelled. Check exact channel names with:

```powershell
Get-WinEvent -ListLog * | Where-Object LogName -like "*Sysmon*" | Select-Object LogName, RecordCount
```

---

## 10. Deploying the SentinelOps detection rules

**Where:** on `wazuh-mgr`.

```bash
sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak
sudo cp detection-rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
sudo chmod 660 /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-logtest -t          # syntax check BEFORE restarting
sudo systemctl restart wazuh-manager
sudo tail -50 /var/ossec/logs/ossec.log       # confirm no rule loading errors
```

Also enable archiving of **all** events (not just alerts) while building the lab — you will
need raw events for `wazuh-logtest`:

```bash
sudo nano /var/ossec/etc/ossec.conf
#   <logall_json>yes</logall_json>      inside <global>
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/archives/archives.json
```

> Turn `logall_json` off again once tuning is finished — it grows quickly.

---

## 11. End-to-end verification

Run this checklist before declaring the lab operational.

| # | Check | Command / location | Expected |
|---|-------|--------------------|----------|
| 1 | Manager healthy | `sudo /var/ossec/bin/wazuh-control status` | all daemons running |
| 2 | Agent Active | *Dashboard → Agents* | green **Active** |
| 3 | Events arriving | `sudo tail -f /var/ossec/logs/archives/archives.json` | JSON lines with `"agent":{"name":"WIN-SOC-EP01"}` |
| 4 | Sysmon flowing | Dashboard *Discover*: `data.win.system.providerName:"Microsoft-Windows-Sysmon"` | hits within the last 15 min |
| 5 | Security log flowing | `data.win.system.channel:"Security"` | hits |
| 6 | PowerShell flowing | `data.win.system.eventID:"4104"` | hits after running a command |
| 7 | Custom rules loaded | `rule.id:100100` after a failed logon test | alert visible |
| 8 | Correlation works | run `Invoke-LabFailedLogons.ps1 -Attempts 12` | `rule.id:100101` alert at level 10 |
| 9 | MITRE populated | *Dashboard → MITRE ATT&CK* | techniques listed |

**The single end-to-end smoke test:**

```powershell
# On WIN-SOC-EP01 (LAB ONLY)
1..12 | ForEach-Object {
    net use \\127.0.0.1\IPC$ /user:labtestuser "WrongPass$_!" 2>$null
    Start-Sleep -Seconds 2
}
```

Then on the dashboard search `rule.id:100101`. An alert within ~60 seconds proves the entire
chain: Windows audit policy → Sysmon/eventlog → agent → manager → decoder → rule →
correlation → indexer → dashboard.

---

## 12. Troubleshooting

### No events at all from the endpoint

```bash
# On the manager
sudo /var/ossec/bin/agent_control -l                  # is the agent Active?
sudo tail -100 /var/ossec/logs/ossec.log              # look for remoted errors
sudo ss -lntp | grep 1514                             # is remoted listening?
```
```powershell
# On the endpoint
Get-Service WazuhSvc
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50
Test-NetConnection 192.168.56.10 -Port 1514
```

| Cause | Fix |
|---|---|
| Agent service stopped | `Restart-Service WazuhSvc` |
| Windows Firewall blocking outbound 1514 | `New-NetFirewallRule -DisplayName "Wazuh Agent" -Direction Outbound -Protocol TCP -RemotePort 1514 -Action Allow` |
| Wrong manager IP in `ossec.conf` | Fix `<address>` in the `<client>` block, restart the service |
| Manager disk full | `df -h`; clear `/var/ossec/logs/archives/` |

### Events arrive but no alerts fire

1. Confirm the event reaches the manager: `sudo tail -f /var/ossec/logs/archives/archives.json`
   (requires `logall_json`).
2. Copy one full JSON line and test it:

   ```bash
   sudo /var/ossec/bin/wazuh-logtest
   ```
   Read the three phases. If **Phase 3** shows a rule ID other than yours, your rule is either
   not loaded, at a lower priority, or its field regex does not match.
3. Check the alert level threshold — alerts below level 3 are not written by default:

   ```bash
   grep -A4 "<alerts>" /var/ossec/etc/ossec.conf
   #   <log_alert_level>3</log_alert_level>
   ```
4. Check for rule syntax errors: `sudo grep -i error /var/ossec/logs/ossec.log | tail -20`

### Field name does not match

Wazuh **lowercases the first letter** of every Windows `EventData` field name:
`TargetUserName` → `targetUserName`, `IpAddress` → `ipAddress`. Confirm the exact spelling by
looking at a real event in *Discover* and expanding the JSON — never guess.

### Dashboard shows "No results match your search criteria"

| Cause | Fix |
|---|---|
| Time picker set to a narrow past window | Set to *Last 24 hours* |
| Endpoint clock differs from manager | Set both to UTC, `w32tm /resync` on Windows |
| Wrong index pattern selected | Select `wazuh-alerts-*` |
| Searching alerts for a level-0 rule | Level 0–2 rules do not create alerts by design |

### Manager will not start after a rule change

```bash
sudo /var/ossec/bin/wazuh-logtest -t          # prints the offending file and line
sudo cp /var/ossec/etc/rules/local_rules.xml.bak /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```
Most common causes: a stray `--` inside an XML comment (illegal in XML), an unescaped `&`,
a duplicate rule ID, or a MITRE technique ID that does not exist in the bundled ATT&CK database.

### High CPU or disk usage on the manager

Usually `logall_json` left enabled, or Sysmon `ImageLoad` accidentally enabled. Disable
`logall_json`, re-check the Sysmon config, and confirm event rates:

```bash
sudo /var/ossec/bin/wazuh-control status
sudo du -sh /var/ossec/logs/*
```

---

## 13. Snapshot and reset procedure

Take a hypervisor snapshot of **both** VMs at these points:

| Snapshot name | When |
|---|---|
| `01-clean-install` | OS installed, static IP set, before any tooling |
| `02-agent-connected` | Wazuh agent Active, audit policy applied |
| `03-fully-instrumented` | Sysmon + PowerShell logging + rules deployed and verified |
| `04-pre-simulation` | Immediately before running any attack simulation |

After each detection scenario, revert to `04-pre-simulation` so every test starts from an
identical baseline. This is what makes the lab **reproducible**, and it is the honest way to
re-run a scenario when you want a cleaner screenshot.
