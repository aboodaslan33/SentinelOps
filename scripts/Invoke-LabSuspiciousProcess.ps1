<#
================================================================================
 SentinelOps - Invoke-LabSuspiciousProcess.ps1
================================================================================
 LAB ONLY. Generates benign process telemetry that matches the suspicious-process
 detections (rules 100130-100134).

 WHAT IT DOES
   Scenario 'Recon'            : runs a burst of READ-ONLY Windows discovery
                                 commands (whoami, hostname, systeminfo, ipconfig,
                                 net user, net localgroup, tasklist) to trigger the
                                 reconnaissance-burst rule 100131.
   Scenario 'StagingDirectory' : copies a harmless Windows binary (whoami.exe) to
                                 C:\Users\Public and runs it from there, to trigger
                                 rule 100133 (execution from a staging directory).
   Scenario 'Masquerade'       : copies whoami.exe to a MISLEADING name
                                 (svchost32.exe) and runs it, to trigger rule
                                 100134 (Image does not match OriginalFileName).

 WHAT IT DOES NOT DO
   * No downloads, no network egress, no persistence, no privilege change.
   * Only read-only commands and copies of a Microsoft-signed system binary.
   * Cleans up any files it creates.

 TELEMETRY GENERATED
   Sysmon EID 1 (process creation)  -> rules 100130, 100131, 100133, 100134

 USAGE
   .\Invoke-LabSuspiciousProcess.ps1 -Scenario Recon
   .\Invoke-LabSuspiciousProcess.ps1 -Scenario StagingDirectory
   .\Invoke-LabSuspiciousProcess.ps1 -Scenario Masquerade
   .\Invoke-LabSuspiciousProcess.ps1 -Scenario All
================================================================================
#>

[CmdletBinding()]
param(
    [ValidateSet('All', 'Recon', 'StagingDirectory', 'Masquerade')]
    [string]$Scenario = 'Recon'
)

Write-Host "=== SentinelOps LAB - suspicious process generator ===" -ForegroundColor Cyan
Write-Host "Scenario: $Scenario  (read-only commands and benign binary copies)" -ForegroundColor Cyan

$publicDir = "C:\Users\Public"
$createdFiles = @()

function Invoke-Recon {
    # A varied burst of distinct discovery binaries. Each is read-only.
    # 7 distinct binaries inside a minute -> rule 100131 (needs 5 distinct/60s).
    Write-Host "[Recon] running discovery commands (whoami, hostname, systeminfo, ipconfig, net, tasklist)" -ForegroundColor Yellow
    $commands = @(
        { whoami /all },
        { hostname },
        { systeminfo },
        { ipconfig /all },
        { net user },
        { net localgroup administrators },
        { tasklist }
    )
    foreach ($c in $commands) {
        try { & $c | Out-Null } catch {}
        Start-Sleep -Seconds 5   # keep them inside the 60s window but distinct
    }
}

function Invoke-StagingDirectory {
    # Copy a genuine, signed system binary to a user-writable directory and run
    # it from there. The BEHAVIOUR (execution from Users\Public) is the signal.
    $src = "$env:SystemRoot\System32\whoami.exe"
    $dst = Join-Path $publicDir "whoami.exe"
    Write-Host "[StagingDirectory] copying whoami.exe to $dst and executing it" -ForegroundColor Yellow
    Copy-Item $src $dst -Force
    $script:createdFiles += $dst
    & $dst /upn 2>&1 | Out-Null
}

function Invoke-Masquerade {
    # Copy whoami.exe under a deceptive name. The on-disk name (svchost32.exe)
    # will NOT match the PE OriginalFileName (whoami.exe) -> rule 100134.
    $src = "$env:SystemRoot\System32\whoami.exe"
    $dst = Join-Path $publicDir "svchost32.exe"
    Write-Host "[Masquerade] copying whoami.exe to a misleading name: $dst" -ForegroundColor Yellow
    Copy-Item $src $dst -Force
    $script:createdFiles += $dst
    & $dst 2>&1 | Out-Null
}

try {
    switch ($Scenario) {
        'Recon'            { Invoke-Recon }
        'StagingDirectory' { Invoke-StagingDirectory }
        'Masquerade'       { Invoke-Masquerade }
        'All'              { Invoke-Recon; Invoke-StagingDirectory; Invoke-Masquerade }
    }
}
finally {
    # Always clean up any binaries we created, even on error.
    foreach ($f in $createdFiles) {
        if (Test-Path $f) { Remove-Item $f -Force; Write-Host "[cleanup] removed $f" -ForegroundColor DarkGray }
    }
}

Write-Host ""
Write-Host "Done. Verify on the Wazuh Dashboard:" -ForegroundColor Green
Write-Host '  rule.id:(100130 OR 100131 OR 100133 OR 100134)' -ForegroundColor Green
Write-Host '  data.win.eventdata.parentImage:* AND agent.name:"WIN-SOC-EP01"' -ForegroundColor Green
