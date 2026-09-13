# SentinelOps — Runbook (nothing → working lab)

A single ordered path from an empty machine to a lab where the detection rules are **proven**
to fire. Follow the steps in order. For every command you get: the **command**, **what proves
it worked**, and **if it fails**. Anything you must do by hand in a GUI or on the VM console is
marked **MANUAL STEP**.

This runbook is the canonical ordered path. It links to the reference docs for exhaustive
detail — [`installation.md`](installation.md), [`../sysmon/README.md`](../sysmon/README.md),
[`../scripts/README.md`](../scripts/README.md), [`dashboard.md`](dashboard.md) — rather than
repeating them.

> **Nothing in this repository has been executed yet.** Until you complete Step 7, every rule is
> UNVERIFIED and every sample event in `tests/logtest/` is a *prediction*, not a capture. See
> [`../audit.md`](../audit.md).

**Order of steps**

0. Prerequisites 1. Wazuh manager 2. Wazuh agent 3. Sysmon
4. Confirm events reach the manager 5. **CRITICAL: correct the test samples from a real event**
6. Deploy the rules 7. Run the logtest harness 8. Run the simulations + capture screenshots
9. Fill one incident report from real evidence

---

## 0. Prerequisites

**MANUAL STEP — provision the VMs in your hypervisor (VirtualBox or VMware).**

| VM | Role | vCPU | RAM | Disk | OS |
|----|------|------|-----|------|----|
| `wazuh-mgr` | Wazuh manager + indexer + dashboard | 2 | 4 GB min, 8 GB recommended | 50 GB | Ubuntu Server 22.04 LTS |
| `WIN-SOC-EP01` | Monitored endpoint | 2 | 4 GB | 60 GB | Windows 10/11 Pro — see the OS requirement below |
| `LAB-ATTACK01` | Attack source (optional) | 1 | 2 GB | 40 GB | Windows 10 or Kali |

**Network — MANUAL STEP.** Put all VMs on a **host-only** network (VirtualBox `vboxnet0`, or
VMware Host-only), suggested subnet `192.168.56.0/24`. Add a NAT adapter **only** while
downloading software, then **disable it** before any attack simulation. Rationale and static-IP
commands: [`installation.md` §2](installation.md).

**Operating-system requirements — do not assume your VM qualifies. Verify each:**

- **Sysmon.** Sysmon requires a supported modern Windows/Server build. The exact minimum
  depends on the Sysmon version you download and is stated on the Sysinternals Sysmon download
  page — **UNVERIFIED here; confirm on that page before you rely on it.** Windows 10/11 Pro
  satisfies current Sysmon builds.
- **PowerShell Script Block Logging (Event ID 4104).** Requires **PowerShell 5.0 or later**.
  PowerShell **5.1 ships with Windows 10 and Windows Server 2016**, so **Windows 10 is the
  practical minimum** for out-of-the-box 4104. On older Windows you must install Windows
  Management Framework 5.1 first, or you will get **no 4104 events at all** and the PowerShell
  detections cannot work. Confirm your version:

  ```powershell
  $PSVersionTable.PSVersion
  ```
  **Proves it worked:** `Major` is `5` (or higher). **If it fails** (Major < 5): install WMF 5.1
  (MANUAL STEP) or use a Windows 10/11 VM; do not continue expecting 4104 events.

- **Command-line auditing / advanced audit policy** (for 4688/4624/4625/4720/4732 etc.) is a
  configuration step, done in Step 3, not an OS-version gate.

**Set both VMs to UTC** so timestamps line up across the endpoint, manager and dashboard —
mismatched time zones are the most common "events aren't arriving" false alarm.

```bash
sudo timedatectl set-timezone UTC && timedatectl        # on Ubuntu
```
```powershell
Set-TimeZone -Id "UTC"; Get-TimeZone                    # on Windows (MANUAL STEP, elevated)
```
**Proves it worked:** both report UTC. **If it fails:** re-run elevated / with sudo.

---

## 1. Install the Wazuh manager (Ubuntu)

**MANUAL STEP — on `wazuh-mgr`, NAT adapter enabled for this step only.**

```bash
sudo apt update && sudo apt upgrade -y
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

**Proves it worked:** the installer ends with a summary naming the dashboard URL and an `admin`
password, e.g. `INFO: Installation finished.` Save that password in a password manager — **do
not commit it** (`.gitignore` already excludes `wazuh-install-files.tar`).

**If it fails:**
- Assistant exits early / "not enough RAM" → give the VM ≥ 4 GB, re-run.
- Network/GPG errors → confirm the NAT adapter is up (`ping -c1 packages.wazuh.com`), re-run.
- Re-running after a partial install → `sudo bash ./wazuh-install.sh -u` (uninstall) then re-run.

**Verify the services:**

```bash
sudo /var/ossec/bin/wazuh-control status
sudo systemctl status wazuh-indexer wazuh-dashboard --no-pager | grep Active
sudo /var/ossec/bin/wazuh-control info      # RECORD the version; some steps are version-sensitive
```
**Proves it worked:** every wazuh daemon reads `is running`; indexer and dashboard show
`active (running)`. **If it fails:** `sudo systemctl restart wazuh-indexer wazuh-manager
wazuh-dashboard`; on 4 GB RAM the indexer can take 2–5 minutes to come up — wait and re-check.

**MANUAL STEP — first login.** Browse to `https://<wazuh-mgr-ip>`, accept the self-signed cert,
log in as `admin`. **Proves it worked:** the Wazuh overview loads. **If it fails:** confirm the
host-only adapter is attached and you can `ping` the manager IP from the host; if the page says
"dashboard not ready", wait for the indexer, then `sudo systemctl restart wazuh-dashboard`.

Then **disable the NAT adapter** on the manager (MANUAL STEP) — the lab is now isolated.

---

## 2. Install the Wazuh agent (Windows)

**MANUAL STEP — download the agent MSI** matching your manager version (from Step 1's
`wazuh-control info`) from the official Wazuh Windows packages page, and copy it to
`WIN-SOC-EP01`.

**MANUAL STEP — install and enrol (elevated PowerShell on `WIN-SOC-EP01`):**

```powershell
msiexec.exe /i C:\Lab\wazuh-agent.msi /q `
    WAZUH_MANAGER="192.168.56.10" WAZUH_AGENT_NAME="WIN-SOC-EP01" `
    WAZUH_REGISTRATION_SERVER="192.168.56.10"
NET START WazuhSvc
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20
```
**Proves it worked:** `ossec.log` shows `Valid key received` and
`Connected to the server (192.168.56.10:1514/tcp)`.

**If it fails:**
- `Unable to connect to '…:1514'` → firewall/IP. Test the path:
  `Test-NetConnection 192.168.56.10 -Port 1514` (must be `True`); on the manager confirm
  `sudo ss -lntp | grep 1514`.
- `Duplicated ID` / stays "Never connected" → remove the old agent on the manager
  (`sudo /var/ossec/bin/manage_agents -r <id>`), delete the agent's `client.keys`, reinstall.

**Verify on the manager:**

```bash
sudo /var/ossec/bin/agent_control -l
```
**Proves it worked:** the agent is listed as `Active`. Also *Dashboard → Agents* shows it green.
**If it fails:** `Restart-Service WazuhSvc` on Windows; recheck time sync (both UTC).

---

## 3. Audit policy, PowerShell logging, and Sysmon (Windows)

**MANUAL STEP — enable auditing and PowerShell logging** exactly as in
[`installation.md` §6–§7](installation.md) (elevated PowerShell). Summary of the essential
commands:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
$sb="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item $sb -Force | Out-Null
Set-ItemProperty $sb EnableScriptBlockLogging 1
```
**Proves it worked:** `auditpol /get /category:*` shows those subcategories as
`Success and Failure`; open a **new** PowerShell window, run any command, then:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 1 |
  Where-Object Id -eq 4104 | Format-List Id, TimeCreated
```
returns a 4104 event. **If it fails:** script-block logging only applies to sessions started
*after* the registry change — open a new window; if still nothing, re-check `$PSVersionTable`
(Step 0) — PS < 5 produces no 4104.

**MANUAL STEP — install Sysmon** with this repo's config (elevated PowerShell). Full guide:
[`../sysmon/README.md`](../sysmon/README.md).

```powershell
# from the folder holding this repo's sysmon/sysmon-config.xml
C:\Lab\Sysmon\Sysmon64.exe -accepteula -i .\sysmon\sysmon-config.xml
Sysmon64.exe -c        # prints the ACTIVE configuration
```
**Proves it worked:** `Sysmon64.exe -c` prints the config; `Get-Service Sysmon64` is `Running`;
a 4104-style check on the Sysmon log returns events:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3 | Format-Table Id, TimeCreated
```
**If it fails:** the config `schemaversion` may not match your Sysmon build (this is UNVERIFIED
in the repo). Read the error from `-i`; if it names the schema, set
`<Sysmon schemaversion="…">` to a value your build accepts (`Sysmon64.exe -? config` lists it),
then `Sysmon64.exe -c .\sysmon\sysmon-config.xml`.

**MANUAL STEP — tell the agent to collect the Sysmon and PowerShell channels** by adding the
`<localfile>` blocks from [`installation.md` §9](installation.md) to
`C:\Program Files (x86)\ossec-agent\ossec.conf`, then `Restart-Service WazuhSvc`.
**Proves it worked:** `ossec.log` shows `Analyzing event log: 'Microsoft-Windows-Sysmon/Operational'`.
**If it fails:** channel name typo — list exact names with
`Get-WinEvent -ListLog * | Where-Object LogName -like "*Sysmon*"`.

---

## 4. Confirm events reach the manager

**MANUAL STEP — enable full event archiving on the manager** so you can inspect raw events
(turn it off again after tuning — it grows fast). Edit `/var/ossec/etc/ossec.conf`, set
`<logall_json>yes</logall_json>` inside `<global>`, then `sudo systemctl restart wazuh-manager`.

Generate one event on Windows (a benign failed logon is enough):

```powershell
net use \\127.0.0.1\IPC$ /user:nosuchuser WrongPass123!   # deliberately fails; lab-local only
```

**On the manager, confirm it arrived** — this is the exact check to run:

```bash
sudo tail -n 50 /var/ossec/logs/archives/archives.json | grep '"WIN-SOC-EP01"'
# or watch live:
sudo tail -f /var/ossec/logs/archives/archives.json
```
**Proves it worked:** JSON lines appear containing `"agent":{"...":"WIN-SOC-EP01"}` and, for the
test above, `"eventID":"4625"`. **If it fails:**
- No file / empty → `logall_json` not applied or manager not restarted.
- Events for other activity but not yours → check the endpoint clock (UTC) and that `WazuhSvc`
  is running; confirm the agent is `Active` (Step 2).
- Nothing at all → agent not forwarding: revisit Step 2 and the firewall on 1514.

---

## 5. CRITICAL STEP — correct the test samples from a REAL event

> **Do not skip this. The files in `tests/logtest/` were written by prediction, not capture.**
> Wazuh lowercases the first letter of every `EventData` field and its decoded JSON shape can
> differ from what the samples assume. **Until you reconcile the samples against a real event,
> the harness in Step 7 proves nothing.**

**MANUAL STEP — capture one real Sysmon process-creation event** and compare it to the matching
sample.

Generate a Sysmon Event ID 1 (any process launch works), then pull the raw decoded JSON from the
manager:

```bash
# grab the most recent Sysmon Event ID 1 the manager decoded
sudo grep '"providerName":"Microsoft-Windows-Sysmon"' /var/ossec/logs/archives/archives.json \
  | grep '"eventID":"1"' | tail -n 1 | python3 -m json.tool
```
**Proves it worked:** you see the real field structure, e.g. `win.system.eventID`,
`win.eventdata.image`, `win.eventdata.commandLine`, `win.eventdata.parentImage`.

**Now compare** against the predicted sample for a process rule, for example:

```bash
python3 -m json.tool tests/logtest/100111.txt
```

Check, field by field:
1. **Field names** — do the real `win.eventdata.*` keys match the sample's keys exactly
   (spelling and first-letter case)?
2. **JSON shape / nesting** — is the real event wrapped the same way (`{"win":{"system":…,
   "eventdata":…}}`) as the sample, or does your Wazuh version frame it differently?
3. **Backslash count** — in the real decoded `image` path, is a path separator one backslash or
   two? This is the exact ambiguity flagged `NEEDS-LOGTEST-VERIFICATION` in
   [`../detection-rules/local_rules.xml`](../detection-rules/local_rules.xml).

**MANUAL STEP — fix the samples, not the rules first:** where the real event differs, edit the
`tests/logtest/*.txt` files so each sample matches the real field names, shape and backslash
count. Only after the samples reflect reality does a Step-7 FAIL mean a rule is actually wrong.
Record what you changed. (Constraint: this runbook does not rewrite the samples for you — they
can only be corrected from a real capture on your build.)

---

## 6. Deploy the detection rules

**MANUAL STEP — on the manager:**

```bash
sudo cp detection-rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
sudo chmod 660 /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-logtest -t          # syntax check BEFORE restart
sudo systemctl restart wazuh-manager
sudo tail -n 40 /var/ossec/logs/ossec.log | grep -iE 'error|rule'
```
**Proves it worked:** `wazuh-logtest -t` returns with no error; `ossec.log` shows no
`Error loading the rules` and no MITRE-ID-not-found error. **If it fails:**
- XML error → the line is named; fix and re-run. (`--` inside an XML comment, unescaped `&`, or a
  duplicate rule ID are the usual causes.)
- `Invalid MITRE technique ID` → that ID is not in your Wazuh build's ATT&CK DB; update Wazuh or
  remove that `<id>` (record it — this is the "MITRE IDs unverified" item in `audit.md`).

---

## 7. Run the logtest harness

This is the step that turns **UNVERIFIED → VERIFIED**.

```bash
sudo bash tests/run-logtest.sh
```
**Proves it worked:** each rule prints `PASS` (target rule fired at the expected level). How the
script reads and what each column means: [`../tests/logtest/expected_results.md`](../tests/logtest/expected_results.md).
**If a rule shows FAIL or LVL?:**
1. Re-run just that rule and read the decode:
   ```bash
   sudo /var/ossec/bin/wazuh-logtest < tests/logtest/100111.txt
   ```
   Read **Phase 2** (did the fields decode with the names the rule expects?) and **Phase 3**
   (which rule id actually matched?).
2. If Phase 2 field names differ from the rule → you missed a correction in Step 5; fix the
   sample or the field name.
3. If a **sibling rule** won (e.g. `100110` instead of `100111`) → expected for overlapping
   rules; confirm the target still appears in the "ALL-MATCHED-IDS" column and decide whether to
   reorder/relevel (see the overlap notes in `expected_results.md`).
4. If a path rule never matches → the backslash count is wrong for your build; adjust the regex
   in `local_rules.xml` (the `NEEDS-LOGTEST-VERIFICATION` rules), redeploy (Step 6), re-run.

**MANUAL STEP — record the outcome.** Only rules that print PASS here may be described as
VERIFIED; update the status column in `README.md` and `audit.md` to match reality. Do not mark a
rule VERIFIED on any other basis.

---

## 8. Run the simulations, confirm alerts, capture screenshots

**MANUAL STEP — for each scenario:** run the safe lab script, confirm the alert on the
dashboard, capture the screenshot. Scripts and safety notes: [`../scripts/README.md`](../scripts/README.md).
Dashboard build: [`dashboard.md`](dashboard.md). Screenshot list, redaction rules and exact
filenames: [`../screenshots/README.md`](../screenshots/README.md).

```powershell
# examples — run on the endpoint (or LAB-ATTACK01 for brute force). LAB ONLY.
.\scripts\Invoke-LabFailedLogons.ps1 -TargetHost 192.168.56.20 -UserName svc-backup -Attempts 12
.\scripts\Invoke-LabPowerShellActivity.ps1 -Scenario All
.\scripts\New-LabTestAccount.ps1 -AccountName lab-svc-update -AddToAdministrators -RemoveAfterSeconds 120
.\scripts\Invoke-LabSuspiciousProcess.ps1 -Scenario All
.\scripts\Invoke-LabPrivilegeActivity.ps1 -AccountName lab-svc-update -CleanUp
```
**Proves it worked (per scenario):** the matching alert appears in *Dashboard → Threat Hunting /
Discover* (e.g. `rule.id:100101` for brute force) within ~60 s, and you save the redacted PNG
under `screenshots/` with the filename from the guide. **If it fails:**
- Script errors on `pwsh`/PowerShell parse → the scripts have not been run before (see
  `audit.md`); read the error and fix on your build.
- No alert but the event is in `archives.json` → the rule did not match: go back to Step 7 for
  that rule id.
- No event in `archives.json` → collection problem: back to Step 4.

**MANUAL STEP — replace the README screenshot placeholders** with the real files once captured.

---

## 9. Fill one incident report from real evidence

**MANUAL STEP.** Pick the matching template in [`../incidents/`](../incidents/) (e.g.
`incident-001-brute-force.md`) and replace every `<PLACEHOLDER>` (`<TIMESTAMP>`, `<HOSTNAME>`,
`<PID>`, `<SOURCE_IP>`, `<LOGON_ID>`, …) and every `<NOT YET MEASURED>` with the real values you
captured: real timestamps from the events, the real host, the real alert IDs, and the metrics
you can now measure. Rename the "EXPECTED EVIDENCE (not yet captured)" sections to reflect that
the evidence is now captured, and set the final status truthfully.

**Proves it worked:** the report contains no `<PLACEHOLDER>` tokens and no `NOT YET MEASURED`,
and every claim is backed by an event you can point to in the dashboard. **If you cannot fill a
field:** leave it as an explicit placeholder rather than inventing a value — an honest gap beats
a fabricated fact.

---

## Done criteria

The lab is genuinely working when [`../audit.md`](../audit.md)'s "Definition of done" is met:
`run-logtest.sh` all PASS, real redacted screenshots exist, dashboards built, Sysmon config
loaded on the endpoint, scripts run and self-cleaned, baseline measured, MITRE IDs confirmed
loaded. Update the status columns in `README.md` and `audit.md` to match what you actually
verified — never ahead of it.
