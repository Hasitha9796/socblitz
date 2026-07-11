# ─────────────────────────────────────────────────────────────────────────────
# SocBlitz Agent installer (Windows)
# One command installs BOTH endpoint components and enrolls them automatically:
#   · Wazuh agent          → SIEM telemetry (logs, FIM, SCA, vulnerability data)
#   · Velociraptor client  → DFIR forensics (artifact collection)
# Run from an elevated (Administrator) PowerShell.
#
# Served pre-templated by the SocBlitz backend — placeholders are substituted
# at download time.
# ─────────────────────────────────────────────────────────────────────────────
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Normally substituted by the backend at download time; raw-template runs can
# override via $env:SOCBLITZ_SERVER / $env:SOCBLITZ_KEY.
$Server = if ($env:SOCBLITZ_SERVER) { $env:SOCBLITZ_SERVER } else { '__SOCBLITZ_SERVER__' }
$Key    = if ($env:SOCBLITZ_KEY)    { $env:SOCBLITZ_KEY }    else { '__ENROLL_KEY__' }
if ("$Server$Key" -match '__') {
    throw 'Unsubstituted placeholders — download this script from the server: iwr "http://<socblitz-host>:5000/api/v1/agent-deploy/install.ps1?key=<AGENT_ENROLL_KEY>"'
}
$Base         = "http://${Server}:5000/api/v1/agent-deploy"
$WazuhVersion = '4.14.5'
$VeloExeUrl   = 'https://github.com/Velocidex/velociraptor/releases/download/v0.76/velociraptor-v0.76.3-windows-amd64.exe'

function Log($msg) { Write-Host "[socblitz-agent] $msg" -ForegroundColor Cyan }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this script from an elevated (Administrator) PowerShell.' }

# ── 1. Wazuh agent ───────────────────────────────────────────────────────────
if (Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue) {
    Log 'Wazuh agent already installed — skipping MSI'
} else {
    Log "Downloading Wazuh agent $WazuhVersion MSI…"
    $msi = Join-Path $env:TEMP 'wazuh-agent.msi'
    Invoke-WebRequest -UseBasicParsing "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion-1.msi" -OutFile $msi
    Log 'Installing Wazuh agent…'
    Start-Process msiexec.exe -Wait -ArgumentList "/i `"$msi`" /q WAZUH_MANAGER=`"$Server`" WAZUH_REGISTRATION_SERVER=`"$Server`""
}
Start-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue
Log "Wazuh agent enrolled to ${Server}:1514/1515"

# ── 2. Velociraptor client ───────────────────────────────────────────────────
$dir = 'C:\Program Files\SocBlitz Agent'
New-Item -ItemType Directory -Force -Path $dir | Out-Null

Log 'Downloading Velociraptor client…'
Invoke-WebRequest -UseBasicParsing $VeloExeUrl -OutFile "$dir\velociraptor.exe"
Invoke-WebRequest -UseBasicParsing "$Base/velociraptor.config.yaml?key=$Key" -OutFile "$dir\client.config.yaml"

Log 'Registering Velociraptor client as a Windows service…'
& "$dir\velociraptor.exe" --config "$dir\client.config.yaml" service install | Out-Null
Start-Service -Name 'Velociraptor' -ErrorAction SilentlyContinue
Log "Velociraptor client enrolled to ${Server}:8010"

Log '──────────────────────────────────────────────────────'
Log "SocBlitz Agent installed on $env:COMPUTERNAME"
Log 'It will appear in the SocBlitz UI (Agents + Forensics) within ~1 minute.'
