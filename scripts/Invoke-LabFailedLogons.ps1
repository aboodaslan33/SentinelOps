<#
================================================================================
 SentinelOps - Invoke-LabFailedLogons.ps1
================================================================================
 LAB ONLY. This script generates FAILED Windows authentication attempts so that
 detection rules 100100/100101/100104 can be validated.

 WHAT IT DOES
   Repeatedly attempts an SMB/IPC$ connection to a target host using a test
   username and a deliberately wrong password. Each attempt Windows rejects is
   recorded on the TARGET as Security Event ID 4625 (An account failed to log
   on), which is exactly the telemetry the brute-force detection consumes.

 WHAT IT DOES NOT DO
   * It does not guess real passwords - the password is always wrong on purpose.
   * It does not exploit anything, install anything, or persist.
   * It does not touch any host other than the one you name.

 TELEMETRY GENERATED
   Target host Security log : Event ID 4625, logon type 3, sub-status
   0xC000006A (wrong password). With enough attempts from one source, Wazuh
   rule 100101 (>=8 in 120s from one IP) fires at level 10.

 SAFETY
   * Run ONLY against a lab VM you own, on an isolated host-only network.
   * Point -TargetHost at your own WIN-SOC-EP01 (e.g. 192.168.56.20), or
     127.0.0.1 to test locally.
   * Requires the target to have "Audit Logon (Failure)" enabled - see
     /documentation/installation.md section 6.

 USAGE
   .\Invoke-LabFailedLogons.ps1 -TargetHost 192.168.56.20 -UserName svc-backup -Attempts 12 -DelaySeconds 3
================================================================================
#>

[CmdletBinding()]
param(
    # The lab host to authenticate against. MUST be a machine you own.
    [Parameter(Mandatory = $true)]
    [string]$TargetHost,

    # A NON-privileged test account name. It does NOT need to exist; if it does
    # not, events will show sub-status 0xC0000064 (unknown user) instead, which
    # is also useful for testing enumeration detection.
    [string]$UserName = "svc-backup",

    # Number of failed attempts to generate.
    [ValidateRange(1, 100)]
    [int]$Attempts = 12,

    # Seconds between attempts. Keep the total burst inside the correlation
    # window (rule 100101 uses 120s) to trigger the burst alert.
    [ValidateRange(0, 60)]
    [int]$DelaySeconds = 3
)

# --- Safety guard: refuse obviously non-lab targets -------------------------
$labRanges = @('192.168.56.', '192.168.', '10.', '172.16.', '127.0.0.1', 'localhost')
if (-not ($labRanges | Where-Object { $TargetHost.StartsWith($_) })) {
    Write-Warning "TargetHost '$TargetHost' is not in a recognised private/lab range."
    $confirm = Read-Host "Type LAB to confirm this is your own isolated lab host"
    if ($confirm -ne 'LAB') { Write-Host "Aborted."; return }
}

Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host " SentinelOps LAB - Failed logon generator" -ForegroundColor Cyan
Write-Host " Target : $TargetHost" -ForegroundColor Cyan
Write-Host " User   : $UserName (wrong password used every time)" -ForegroundColor Cyan
Write-Host " Count  : $Attempts attempts, $DelaySeconds s apart" -ForegroundColor Cyan
Write-Host " Expect : Event ID 4625 on the target; Wazuh rule 100101 at level 10" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan

$share = "\\$TargetHost\IPC$"

for ($i = 1; $i -le $Attempts; $i++) {
    # Each attempt uses a different, always-wrong password. 'net use' triggers a
    # network (type 3) logon on the target, which is rejected and logged.
    $wrongPassword = "WrongPassword_$i!$(Get-Random -Minimum 1000 -Maximum 9999)"

    # Redirect all output; we only care that the attempt was made and rejected.
    net use $share /user:$UserName $wrongPassword 2>&1 | Out-Null

    if ($LASTEXITCODE -ne 0) {
        Write-Host ("[{0:00}/{1:00}] {2:HH:mm:ss} - attempt rejected as expected (4625 generated on target)" -f `
            $i, $Attempts, (Get-Date)) -ForegroundColor Yellow
    } else {
        # This should not happen with a wrong password; clean up if it does.
        Write-Warning "[$i] Connection unexpectedly SUCCEEDED - removing it."
        net use $share /delete 2>&1 | Out-Null
    }

    if ($i -lt $Attempts) { Start-Sleep -Seconds $DelaySeconds }
}

Write-Host ""
Write-Host "Done. Verify on the Wazuh Dashboard:" -ForegroundColor Green
Write-Host '  rule.id:(100100 OR 100101)' -ForegroundColor Green
Write-Host '  data.win.system.eventID:4625 AND data.win.eventdata.targetUserName:"'$UserName'"' -ForegroundColor Green
Write-Host "On the target, confirm locally with:" -ForegroundColor Green
Write-Host '  Get-WinEvent -FilterHashtable @{LogName=''Security''; Id=4625} -MaxEvents 5' -ForegroundColor Green
