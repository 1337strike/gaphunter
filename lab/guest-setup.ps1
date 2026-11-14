<#
  GapHunter guest setup: telemetry for the Windows 11 lab VM.

  Installs standalone Sysinternals Sysmon with the sysmon-modular configuration, turns on
  process-creation auditing with command lines and PowerShell script block logging, and
  enlarges the event logs. Safe to run again: an existing Sysmon gets the config updated.

  Needs internet (run it while the VM is still on libvirt's default network) and an
  administrator account. From the host:

    scp lab/guest-setup.ps1 labadmin@VM_IP:C:/Users/labadmin/guest-setup.ps1
    ssh labadmin@VM_IP "powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\labadmin\guest-setup.ps1"

  Why standalone Sysmon and not the built-in Windows feature: the standalone release is
  the same on every Windows build, its version is recorded in GapHunter's run manifest,
  and it is what published Sigma rules are written against. The two cannot run together,
  so the script stops if the built-in feature is enabled.
#>
param(
    # sysmon-modular publishes its ready-made configs as release assets. Pinned for
    # reproducibility; pass -ConfigRelease latest to take the newest one.
    [string]$ConfigRelease = 'configs-a45dedb13a43'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Tools = 'C:\Tools\Sysmon'
$SysmonZip = 'https://download.sysinternals.com/files/Sysmon.zip'
if ($ConfigRelease -eq 'latest') {
    $ConfigUrl = 'https://github.com/olafhartong/sysmon-modular/releases/latest/download/sysmonconfig.xml'
} else {
    $ConfigUrl = "https://github.com/olafhartong/sysmon-modular/releases/download/$ConfigRelease/sysmonconfig.xml"
}

function Step($text) { Write-Output "==> $text" }

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this as an administrator (the lab account must be in the Administrators group).'
}

Step 'Checking that the built-in Windows Sysmon feature is not enabled'
$builtin = $null
try { $builtin = Get-WindowsOptionalFeature -Online -FeatureName Sysmon -ErrorAction Stop } catch { }
if ($builtin -and $builtin.State -eq 'Enabled') {
    throw 'The built-in Sysmon feature is enabled. Disable it (Disable-WindowsOptionalFeature -Online -FeatureName Sysmon), reboot, and run this again.'
}

Step 'Downloading Sysinternals Sysmon and the sysmon-modular configuration'
New-Item -ItemType Directory -Force -Path $Tools | Out-Null
Invoke-WebRequest -UseBasicParsing -Uri $SysmonZip -OutFile "$Tools\Sysmon.zip"
Expand-Archive -Path "$Tools\Sysmon.zip" -DestinationPath $Tools -Force
Invoke-WebRequest -UseBasicParsing -Uri $ConfigUrl -OutFile "$Tools\sysmonconfig.xml"

$exe = "$Tools\Sysmon64.exe"
if (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue) {
    Step 'Sysmon is already installed: updating its configuration'
    & $exe -c "$Tools\sysmonconfig.xml" | Out-Null
} else {
    Step 'Installing Sysmon'
    & $exe -accepteula -i "$Tools\sysmonconfig.xml" | Out-Null
}
if ($LASTEXITCODE -ne 0) { throw "Sysmon64.exe exited with code $LASTEXITCODE" }

Step 'Auditing process creation, with command lines'
& auditpol.exe /set /subcategory:"Process Creation" /success:enable | Out-Null
if ($LASTEXITCODE -ne 0) {
    # The subcategory name is localised; fall back to its GUID.
    & auditpol.exe /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
}
New-Item -Force -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
    -Name ProcessCreationIncludeCmdLine_Enabled -Type DWord -Value 1

Step 'Turning on PowerShell script block logging'
New-Item -Force -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
    -Name EnableScriptBlockLogging -Type DWord -Value 1

Step 'Enlarging the event logs so nothing is overwritten during a session'
& wevtutil.exe sl 'Microsoft-Windows-Sysmon/Operational' /ms:268435456
& wevtutil.exe sl 'Microsoft-Windows-PowerShell/Operational' /ms:134217728
& wevtutil.exe sl 'Security' /ms:268435456

Step 'Result'
$svc = Get-CimInstance Win32_Service -Filter "Name='Sysmon64'"
$version = (Get-Item $exe).VersionInfo.FileVersion
$hash = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters' -ErrorAction SilentlyContinue).ConfigHash
$recent = (Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object).Count
$pcAudit = (& auditpol.exe /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}") -join ' '
Write-Output ("Sysmon service : {0} ({1})" -f $svc.State, $svc.StartMode)
Write-Output ("Sysmon version : {0}" -f $version)
Write-Output ("Config release : sysmon-modular {0}" -f $ConfigRelease)
Write-Output ("Config hash    : {0}" -f $hash)
Write-Output ("Sysmon events  : {0} recent events readable" -f $recent)
Write-Output ("Process audit  : {0}" -f $(if ($pcAudit -match 'Success') { 'on' } else { 'CHECK MANUALLY' }))
if ($svc.State -ne 'Running') { throw 'Sysmon is not running.' }
Write-Output 'guest-setup: OK'
