<#
================================================================================
 SentinelOps - Invoke-LabPrivilegeActivity.ps1
================================================================================
 LAB ONLY. Produces privilege-escalation-related telemetry using ORDINARY
 administrative actions (no exploit, no vulnerability, no third-party tools), so
 that rules 100140/100141/100143/100144 can be validated.

 WHAT IT DOES (all reversible, all cleaned up)
   1. Ensures a lab account exists and adds it to Administrators   -> 4732 (100140)
   2. Creates a scheduled task that runs 'cmd /c echo' as SYSTEM   -> 4698 (100143)
                                                                       schtasks (100144)
   3. Starts an elevated process to produce a privileged logon     -> 4672 (100141)
   Then it REMOVES the task and the group membership again.

 WHAT IT DOES NOT DO
   * It does not exploit any weakness or bypass any control.
   * The scheduled task action is a harmless 'echo' - no payload.
   * It does not disable Defender, clear logs, or persist beyond cleanup.

 IMPORTANT
   This demonstrates DETECTION of the telemetry that privilege escalation
   produces. It is not, and must not be used as, a technique for gaining
   privilege on any system you do not own.

 TELEMETRY GENERATED
   Security 4732 (Administrators membership)  -> rule 100140
   Security 4672 (special privileges)          -> rule 100141
   Security 4698 + schtasks.exe /create /ru SYSTEM -> rules 100143, 100144

 REQUIRES
   * Run as Administrator.
   * Audit policy from installation.md section 6 applied.

 USAGE
   .\Invoke-LabPrivilegeActivity.ps1 -AccountName lab-svc-update -CleanUp
================================================================================
#>

[CmdletBinding()]
param(
    [ValidatePattern('^lab[-_].+')]
    [string]$AccountName = "lab-svc-update",

    # Remove the task and group membership at the end (recommended).
    [switch]$CleanUp,

    [string]$TaskName = "SentinelOpsLabTask"
)

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Error "Run this script from an ELEVATED PowerShell window."; return }

Write-Host "=== SentinelOps LAB - privilege activity generator ===" -ForegroundColor Cyan
Write-Host "All actions are ordinary administration and are reversed at the end." -ForegroundColor Cyan

# --- Step 0: ensure the lab account exists ----------------------------------
if (-not (Get-LocalUser -Name $AccountName -ErrorAction SilentlyContinue)) {
    Add-Type -AssemblyName System.Web
    $secure = ConvertTo-SecureString ([System.Web.Security.Membership]::GeneratePassword(20,5)) -AsPlainText -Force
    New-LocalUser -Name $AccountName -Password $secure `
        -Description "LAB ONLY - SentinelOps privilege test" -PasswordNeverExpires | Out-Null
    Write-Host "[setup] created lab account '$AccountName' (4720)" -ForegroundColor Yellow
}

# --- Step 1: add to Administrators (4732) -----------------------------------
if (-not (Get-LocalGroupMember -Group "Administrators" -Member $AccountName -ErrorAction SilentlyContinue)) {
    Add-LocalGroupMember -Group "Administrators" -Member $AccountName
    Write-Host "[step 1] added '$AccountName' to Administrators (4732 -> rule 100140)" -ForegroundColor Red
}

# --- Step 2: create a SYSTEM scheduled task (4698 + schtasks) ----------------
Write-Host "[step 2] creating scheduled task '$TaskName' running as SYSTEM (4698 -> rules 100143/100144)" -ForegroundColor Red
# Benign action: echo to nowhere. Runs at boot, as SYSTEM, HighestAvailable.
schtasks.exe /create /tn $TaskName /tr "cmd.exe /c echo SentinelOps-lab" `
    /sc onstart /ru SYSTEM /rl HIGHEST /f | Out-Null

# --- Step 3: privileged logon (4672) ----------------------------------------
Write-Host "[step 3] starting an elevated process to produce a privileged logon (4672 -> rule 100141)" -ForegroundColor Red
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "whoami /priv & exit" -Verb RunAs -Wait -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Verify on the Wazuh Dashboard:" -ForegroundColor Green
Write-Host '  rule.id:(100140 OR 100141 OR 100143 OR 100144)' -ForegroundColor Green
Write-Host ('  data.win.eventdata.memberName:*{0}* OR data.win.eventdata.taskName:*{1}*' -f $AccountName, $TaskName) -ForegroundColor Green

# --- Cleanup ----------------------------------------------------------------
if ($CleanUp) {
    Write-Host "`n[cleanup] reversing all changes..." -ForegroundColor DarkGray
    schtasks.exe /delete /tn $TaskName /f 2>&1 | Out-Null
    try { Remove-LocalGroupMember -Group "Administrators" -Member $AccountName -ErrorAction SilentlyContinue } catch {}
    Write-Host "[cleanup] removed scheduled task and Administrators membership." -ForegroundColor DarkGray
    Write-Host "[cleanup] the lab account '$AccountName' was left in place; remove with:" -ForegroundColor DarkGray
    Write-Host ("           .\New-LabTestAccount.ps1 -AccountName {0} -RemoveOnly" -f $AccountName) -ForegroundColor DarkGray
} else {
    Write-Host "`nRun again with -CleanUp, or reverse manually:" -ForegroundColor DarkGray
    Write-Host ("  schtasks /delete /tn {0} /f" -f $TaskName) -ForegroundColor DarkGray
    Write-Host ("  Remove-LocalGroupMember -Group Administrators -Member {0}" -f $AccountName) -ForegroundColor DarkGray
}
