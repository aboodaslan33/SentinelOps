<#
================================================================================
 SentinelOps - Invoke-LabPowerShellActivity.ps1
================================================================================
 LAB ONLY. Generates benign but detection-relevant PowerShell telemetry so that
 rules 100110-100115 can be validated.

 WHAT IT DOES
   Runs PowerShell in ways that LOOK like the techniques attackers use, while
   doing nothing harmful:
     * launches powershell.exe with -EncodedCommand / -WindowStyle Hidden /
       -ExecutionPolicy Bypass, where the decoded command only writes text;
     * produces a script block containing a download-cradle STRING that is
       logged (Event 4104) but resolves to a local lab URL or is never invoked;
     * optionally performs a REAL download from a LOCAL lab web server only, to
       demonstrate Sysmon Event ID 3 (network connection).

 WHAT IT DOES NOT DO
   * No malware, no remote/internet destinations, no in-memory execution of
     downloaded code, no persistence, no defence tampering.

 TELEMETRY GENERATED
   Sysmon EID 1 (encoded / hidden-window command lines)  -> rules 100110, 100111
   PowerShell 4104 (decoded script block with cradle text) -> rule 100113
   Sysmon EID 3 (only if -DownloadFromLabServer is used)   -> rule 100114

 PREREQUISITES
   PowerShell Script Block Logging enabled (installation.md section 7) and
   Sysmon installed with this repo's config.

 USAGE
   .\Invoke-LabPowerShellActivity.ps1 -Scenario All
   .\Invoke-LabPowerShellActivity.ps1 -Scenario Encoded
   .\Invoke-LabPowerShellActivity.ps1 -Scenario Cradle -DownloadFromLabServer -LabServer 192.168.56.30 -LabPort 8000
================================================================================
#>

[CmdletBinding()]
param(
    [ValidateSet('All', 'Encoded', 'HiddenWindow', 'Cradle')]
    [string]$Scenario = 'All',

    # If set, actually fetch a file from a LOCAL lab web server (Sysmon EID 3).
    # Never point this at anything outside your lab.
    [switch]$DownloadFromLabServer,

    [string]$LabServer = '192.168.56.30',
    [int]$LabPort = 8000
)

Write-Host "=== SentinelOps LAB - PowerShell activity generator ===" -ForegroundColor Cyan
Write-Host "Scenario: $Scenario  (all actions are benign)" -ForegroundColor Cyan

function Invoke-EncodedScenario {
    # Build a Base64 -EncodedCommand whose decoded content ONLY writes a string.
    # This reproduces the -enc pattern that rule 100111 detects, safely.
    $inner   = "Write-Output 'SentinelOps lab: encoded command executed (benign)'"
    $bytes   = [Text.Encoding]::Unicode.GetBytes($inner)
    $encoded = [Convert]::ToBase64String($bytes)

    Write-Host "[Encoded] launching powershell.exe -EncodedCommand (decodes to a harmless Write-Output)" -ForegroundColor Yellow
    Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $encoded `
        -WindowStyle Normal -Wait
}

function Invoke-HiddenWindowScenario {
    # -WindowStyle Hidden + -NoProfile + bypass: the "run silently" pattern.
    Write-Host "[HiddenWindow] launching powershell.exe -w hidden -nop -ExecutionPolicy Bypass" -ForegroundColor Yellow
    Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", `
                      "-Command", "Write-Output 'SentinelOps lab: hidden-window run (benign)'; Start-Sleep -Milliseconds 500" `
        -Wait
}

function Invoke-CradleScenario {
    # Create a script block containing download-cradle TEXT. Event 4104 logs the
    # de-obfuscated text, which is what rule 100113 matches on. By default the
    # cradle is only DEFINED (as a string/here-string), never executed.
    Write-Host "[Cradle] emitting a script block containing Net.WebClient / DownloadString text (logged via 4104)" -ForegroundColor Yellow

    $cradleText = @'
# SentinelOps lab - benign representation of a download cradle (NOT executed)
$client = New-Object System.Net.WebClient
$demoUrl = "http://LAB-SERVER:PORT/lab-test.txt"
# In a real attack this would be: IEX ($client.DownloadString($demoUrl))
Write-Output "Cradle text generated for detection testing only"
'@
    $cradleText = $cradleText.Replace('LAB-SERVER', $LabServer).Replace('PORT', "$LabPort")

    # Execute the SCRIPT (which contains the cradle text) so 4104 records it.
    # The DownloadString itself is commented out, so nothing is fetched here.
    $sb = [ScriptBlock]::Create($cradleText)
    & $sb

    if ($DownloadFromLabServer) {
        # OPTIONAL real fetch from the LOCAL lab server only -> Sysmon EID 3.
        $url = "http://${LabServer}:${LabPort}/lab-test.txt"
        Write-Host "[Cradle] performing a REAL download from LAB server only: $url" -ForegroundColor Yellow
        try {
            $tmp = Join-Path $env:TEMP "lab-test.txt"
            Invoke-WebRequest -Uri $url -OutFile $tmp -TimeoutSec 5 -UseBasicParsing
            Write-Host "[Cradle] saved to $tmp (Sysmon EID 3 + EID 11 generated)" -ForegroundColor Yellow
        } catch {
            Write-Warning "Lab download failed (is the lab web server running?). Non-fatal: $($_.Exception.Message)"
        }
    }
}

switch ($Scenario) {
    'Encoded'      { Invoke-EncodedScenario }
    'HiddenWindow' { Invoke-HiddenWindowScenario }
    'Cradle'       { Invoke-CradleScenario }
    'All'          { Invoke-EncodedScenario; Invoke-HiddenWindowScenario; Invoke-CradleScenario }
}

Write-Host ""
Write-Host "Done. Verify on the Wazuh Dashboard:" -ForegroundColor Green
Write-Host '  rule.id:(100110 OR 100111 OR 100113 OR 100114)' -ForegroundColor Green
Write-Host '  data.win.system.eventID:4104 AND agent.name:"WIN-SOC-EP01"' -ForegroundColor Green
