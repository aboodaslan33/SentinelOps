<#
================================================================================
 SentinelOps - Get-LabEventSummary.ps1
================================================================================
 LAB HELPER (read-only). Collects a quick summary of the Windows security-relevant
 events on the local endpoint, to confirm the lab is producing telemetry and to
 support an investigation. It READS logs only - it changes nothing.

 WHAT IT REPORTS
   * Count of key Security event IDs (4625, 4624, 4720, 4732, 4672, 4698, 1102)
     in the chosen time window.
   * Count of Sysmon events by Event ID.
   * Recent PowerShell 4104 script-block events.
   * Current local users and Administrators membership.

 USAGE
   .\Get-LabEventSummary.ps1 -Hours 24
   .\Get-LabEventSummary.ps1 -Hours 2 -ExportPath C:\Lab\Evidence
================================================================================
#>

[CmdletBinding()]
param(
    [int]$Hours = 24,
    [string]$ExportPath
)

$start = (Get-Date).AddHours(-$Hours)
Write-Host "=== SentinelOps LAB - event summary (last $Hours h, since $start UTC-local) ===" -ForegroundColor Cyan

# --- Key Security events ----------------------------------------------------
$securityIds = @{
    4625 = "Failed logon";     4624 = "Successful logon";  4720 = "Account created"
    4732 = "Added to group";   4672 = "Special privileges"; 4698 = "Scheduled task created"
    1102 = "Security log cleared"
}
Write-Host "`n-- Security log --" -ForegroundColor Cyan
foreach ($id in $securityIds.Keys | Sort-Object) {
    $n = (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$id; StartTime=$start} -ErrorAction SilentlyContinue |
          Measure-Object).Count
    "{0,-6} {1,-28} : {2}" -f $id, $securityIds[$id], $n
}

# --- Sysmon events by ID ----------------------------------------------------
Write-Host "`n-- Sysmon (Microsoft-Windows-Sysmon/Operational) --" -ForegroundColor Cyan
try {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$start} -ErrorAction Stop |
        Group-Object Id | Sort-Object { [int]$_.Name } |
        ForEach-Object { "EID {0,-4} : {1}" -f $_.Name, $_.Count }
} catch { Write-Warning "Sysmon log not available: $($_.Exception.Message)" }

# --- PowerShell script blocks -----------------------------------------------
Write-Host "`n-- PowerShell script blocks (4104), last 5 --" -ForegroundColor Cyan
try {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$start} -MaxEvents 5 -ErrorAction Stop |
        Select-Object TimeCreated, Id, @{n='Snippet';e={ ($_.Message -split "`n" | Select-Object -First 1) }} |
        Format-Table -AutoSize
} catch { Write-Warning "PowerShell Operational log not available." }

# --- Local account state ----------------------------------------------------
Write-Host "`n-- Local users --" -ForegroundColor Cyan
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet | Format-Table -AutoSize
Write-Host "-- Administrators group --" -ForegroundColor Cyan
Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass | Format-Table -AutoSize

# --- Optional export --------------------------------------------------------
if ($ExportPath) {
    if (-not (Test-Path $ExportPath)) { New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null }
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    Get-LocalUser | Export-Csv (Join-Path $ExportPath "localusers-$stamp.csv") -NoTypeInformation
    Get-LocalGroupMember -Group "Administrators" | Export-Csv (Join-Path $ExportPath "admins-$stamp.csv") -NoTypeInformation
    Write-Host "`nExported account state to $ExportPath" -ForegroundColor Green
}

Write-Host "`nRead-only summary complete. No changes were made." -ForegroundColor Green
