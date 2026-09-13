<#
================================================================================
 SentinelOps - New-LabTestAccount.ps1
================================================================================
 LAB ONLY. Creates (and cleans up) a local test account so that account-creation
 and privilege-escalation detections (rules 100120/100121/100140) can be tested.

 WHAT IT DOES
   * Creates a clearly-labelled local user account.
   * Optionally adds it to the local Administrators group (to trigger 100121/100140).
   * Optionally removes the account again after a delay so the lab is left clean.

 WHAT IT DOES NOT DO
   * It does not create a real backdoor: the account is named for the lab, uses a
     random throwaway password, and is intended to be removed.
   * It does nothing on any host other than the local machine.

 TELEMETRY GENERATED
   Security 4720 (account created)              -> rule 100120
   Security 4722/4724 (enabled / password set)  -> rule 100122
   Security 4732 (added to Administrators)       -> rules 100140, 100121
   Sysmon  EID 1  (New-LocalUser / net.exe)     -> process context

 REQUIRES
   * Run as Administrator.
   * "Audit User Account Management" and "Audit Security Group Management"
     enabled for Success (installation.md section 6).

 USAGE
   .\New-LabTestAccount.ps1 -AccountName lab-svc-update -AddToAdministrators -RemoveAfterSeconds 120
   .\New-LabTestAccount.ps1 -AccountName lab-test01                       # create only
   .\New-LabTestAccount.ps1 -AccountName lab-test01 -RemoveOnly           # cleanup
================================================================================
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^lab[-_].+')]   # force a lab- prefix so real accounts cannot be targeted
    [string]$AccountName,

    [switch]$AddToAdministrators,

    # If > 0, the account is automatically removed after this many seconds.
    [int]$RemoveAfterSeconds = 0,

    # Just remove a previously created lab account and exit.
    [switch]$RemoveOnly
)

# --- Must be elevated -------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Error "Run this script from an ELEVATED PowerShell window."; return }

function Remove-LabAccount {
    param([string]$Name)
    if (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue) {
        try { Remove-LocalGroupMember -Group "Administrators" -Member $Name -ErrorAction SilentlyContinue } catch {}
        Remove-LocalUser -Name $Name
        Write-Host "[cleanup] Removed local account '$Name' (Security 4726 generated)" -ForegroundColor Yellow
    } else {
        Write-Host "[cleanup] Account '$Name' does not exist - nothing to remove." -ForegroundColor DarkGray
    }
}

Write-Host "=== SentinelOps LAB - test account generator ===" -ForegroundColor Cyan

if ($RemoveOnly) { Remove-LabAccount -Name $AccountName; return }

if (Get-LocalUser -Name $AccountName -ErrorAction SilentlyContinue) {
    Write-Warning "Account '$AccountName' already exists. Use -RemoveOnly first."
    return
}

# --- Create the account with a random throwaway password --------------------
Add-Type -AssemblyName System.Web
$plain  = [System.Web.Security.Membership]::GeneratePassword(20, 5)
$secure = ConvertTo-SecureString $plain -AsPlainText -Force
# The plaintext is discarded immediately - it is never written to disk or logs.
$plain  = $null

New-LocalUser -Name $AccountName -Password $secure `
    -FullName "SentinelOps Lab Test Account" `
    -Description "LAB ONLY - created by New-LabTestAccount.ps1 for detection testing" `
    -PasswordNeverExpires | Out-Null
Write-Host "[create] Local account '$AccountName' created (Security 4720)" -ForegroundColor Yellow

if ($AddToAdministrators) {
    Add-LocalGroupMember -Group "Administrators" -Member $AccountName
    Write-Host "[escalate] '$AccountName' added to Administrators (Security 4732 -> rules 100140/100121)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Verify on the Wazuh Dashboard:" -ForegroundColor Green
Write-Host '  rule.id:(100120 OR 100121 OR 100140)' -ForegroundColor Green
Write-Host ('  data.win.eventdata.targetUserName:"{0}"' -f $AccountName) -ForegroundColor Green

if ($RemoveAfterSeconds -gt 0) {
    Write-Host "`nWaiting $RemoveAfterSeconds s before automatic cleanup..." -ForegroundColor DarkGray
    Start-Sleep -Seconds $RemoveAfterSeconds
    Remove-LabAccount -Name $AccountName
    Write-Host "Lab restored to clean state." -ForegroundColor Green
} else {
    Write-Host "`nRemember to clean up when finished:" -ForegroundColor DarkGray
    Write-Host ("  .\New-LabTestAccount.ps1 -AccountName {0} -RemoveOnly" -f $AccountName) -ForegroundColor DarkGray
}
