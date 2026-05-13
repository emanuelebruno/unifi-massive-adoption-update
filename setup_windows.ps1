$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
} catch {
}

$repoOwner = 'emanuelebruno'
$repoName = 'unifi-massive-adoption-update'
$refsToTry = @('main', 'master')
$rawBase = "https://raw.githubusercontent.com/$repoOwner/$repoName"

function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host ('=' * $Title.Length)
    Write-Host $Title
    Write-Host ('=' * $Title.Length)
}

function Get-CommandPathOrNull([string]$CommandName) {
    $cmd = Get-Command $CommandName -ErrorAction SilentlyContinue
    if (-not $cmd) { return $null }
    return $cmd.Source
}

function Download-File {
    param(
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    $destinationDir = Split-Path -Parent $DestinationPath
    if ($destinationDir -and -not (Test-Path -LiteralPath $destinationDir)) {
        New-Item -ItemType Directory -Path $destinationDir | Out-Null
    }

    $hasBits = $false
    if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) { $hasBits = $true }

    foreach ($ref in $refsToTry) {
        $url = "$rawBase/$ref/$RelativePath"
        try {
            if ($hasBits) {
                Start-BitsTransfer -Source $url -Destination $DestinationPath -ErrorAction Stop
            } else {
                $iwrParams = @{ Uri = $url; OutFile = $DestinationPath; ErrorAction = 'Stop' }
                if ($PSVersionTable.PSVersion.Major -lt 6) { $iwrParams.UseBasicParsing = $true }
                Invoke-WebRequest @iwrParams
            }
            return $true
        } catch {
            if (Test-Path -LiteralPath $DestinationPath) {
                Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
            }
        }
    }

    return $false
}

function Resolve-Python {
    $py = Get-CommandPathOrNull -CommandName 'py'
    if ($py) { return @{ Launcher = 'py'; Exists = $true } }
    $python = Get-CommandPathOrNull -CommandName 'python'
    if ($python) { return @{ Launcher = 'python'; Exists = $true } }
    return @{ Launcher = $null; Exists = $false }
}

function Ensure-Winget {
    $winget = Get-CommandPathOrNull -CommandName 'winget'
    if ($winget) { return $true }

    Write-Host ''
    Write-Host 'winget non è disponibile su questo sistema.'
    Write-Host 'Installa App Installer (Microsoft Store) oppure usa un metodo alternativo per installare:'
    Write-Host '- Python 3.12+ (python.exe o py.exe in PATH)'
    Write-Host '- PuTTY (plink.exe e pscp.exe in PATH)'
    Write-Host ''
    Write-Host 'Poi riesegui setup_windows.ps1.'
    return $false
}

function Ensure-Python {
    $pyInfo = Resolve-Python
    if ($pyInfo.Exists) { return $pyInfo.Launcher }

    Write-Section 'Installazione Python (winget)'
    if (-not (Ensure-Winget)) { exit 1 }

    & winget install Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) {
        throw "Installazione Python fallita (exit code: $LASTEXITCODE)."
    }

    $pyInfo = Resolve-Python
    if (-not $pyInfo.Exists) {
        Write-Host ''
        Write-Host 'Python risulta installato ma non è disponibile nel PATH della sessione corrente.'
        Write-Host 'Apri una nuova finestra PowerShell e riesegui setup_windows.ps1.'
        exit 1
    }

    return $pyInfo.Launcher
}

function Ensure-Putty {
    $plink = Get-CommandPathOrNull -CommandName 'plink.exe'
    $pscp = Get-CommandPathOrNull -CommandName 'pscp.exe'
    if ($plink -and $pscp) { return }

    Write-Section 'Installazione PuTTY (winget)'
    if (-not (Ensure-Winget)) { exit 1 }

    & winget install PuTTY.PuTTY --silent --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) {
        throw "Installazione PuTTY fallita (exit code: $LASTEXITCODE)."
    }

    $plink = Get-CommandPathOrNull -CommandName 'plink.exe'
    $pscp = Get-CommandPathOrNull -CommandName 'pscp.exe'
    if (-not $plink -or -not $pscp) {
        Write-Host ''
        Write-Host 'PuTTY risulta installato ma plink.exe/pscp.exe non sono disponibili nel PATH della sessione corrente.'
        Write-Host 'Apri una nuova finestra PowerShell e riesegui setup_windows.ps1.'
        exit 1
    }
}

Write-Section 'Setup UAP-IW Tools (Windows)'
Write-Host ('Cartella corrente: ' + (Get-Location).Path)

$requiredFiles = @(
    'uap_iw_phase1_discovery.py',
    'uap_iw_phase2_firmware_update.py',
    'requirements.txt'
)

Write-Section 'Verifica repository locale / download da GitHub'
foreach ($file in $requiredFiles) {
    if (-not (Test-Path -LiteralPath ".\$file")) {
        Write-Host "Manca $file -> download..."
        $ok = Download-File -RelativePath $file -DestinationPath ".\$file"
        if (-not $ok) { throw "Download fallito per $file dal repository pubblico." }
    } else {
        Write-Host "OK: $file"
    }
}

if (-not (Test-Path -LiteralPath '.\firmware')) { New-Item -ItemType Directory -Path '.\firmware' | Out-Null }
if (-not (Test-Path -LiteralPath '.\reports')) { New-Item -ItemType Directory -Path '.\reports' | Out-Null }

$firmwareRel = 'firmware/BZ.qca933x.v4.3.28.11361.210128.2309.bin'
$firmwareLocal = ".\firmware\BZ.qca933x.v4.3.28.11361.210128.2309.bin"

Write-Section 'Firmware'
if (-not (Test-Path -LiteralPath $firmwareLocal)) {
    Write-Host "Manca $firmwareLocal -> download..."
    $ok = Download-File -RelativePath $firmwareRel -DestinationPath $firmwareLocal
    if (-not $ok) { throw "Download fallito per $firmwareRel dal repository pubblico." }
}

if (-not (Test-Path -LiteralPath $firmwareLocal)) {
    throw "Firmware non trovato: $firmwareLocal"
}

$firmwareItem = Get-Item -LiteralPath $firmwareLocal
if ($firmwareItem.Length -lt 1048576) {
    throw "Firmware troppo piccolo o corrotto (size: $($firmwareItem.Length) bytes): $firmwareLocal"
}

try {
    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $firmwareLocal
    Write-Host ("OK: firmware presente (SHA256: {0})" -f $hash.Hash)
} catch {
    Write-Host 'OK: firmware presente'
}

Write-Section 'Python'
$pythonLauncher = Ensure-Python
& $pythonLauncher --version

Write-Section 'PuTTY'
Ensure-Putty
Write-Host ('plink.exe: ' + (Get-CommandPathOrNull -CommandName 'plink.exe'))
Write-Host ('pscp.exe:  ' + (Get-CommandPathOrNull -CommandName 'pscp.exe'))

Write-Section 'Virtualenv (.venv)'
$venvPython = '.\.venv\Scripts\python.exe'
if (Test-Path -LiteralPath $venvPython) {
    Write-Host 'OK: .venv già presente'
} else {
    if (Test-Path -LiteralPath '.\.venv') {
        throw 'La cartella .venv esiste ma .venv\Scripts\python.exe non è presente. Elimina .venv e riesegui.'
    }
    & $pythonLauncher -m venv .venv
    if (-not (Test-Path -LiteralPath $venvPython)) {
        throw 'Creazione venv fallita: .venv\Scripts\python.exe non trovato.'
    }
}

Write-Section 'Install requirements'
& $venvPython -m pip install -r .\requirements.txt
if ($LASTEXITCODE -ne 0) {
    throw "pip install fallito (exit code: $LASTEXITCODE)."
}

Write-Section 'py_compile'
& $venvPython -m py_compile .\uap_iw_phase1_discovery.py
& $venvPython -m py_compile .\uap_iw_phase2_firmware_update.py

Write-Section 'Verifica finale firmware'
if (-not (Test-Path -LiteralPath $firmwareLocal)) {
    throw "Firmware non trovato: $firmwareLocal"
}
Write-Host "OK: $firmwareLocal"

Write-Section 'Comandi pronti (NON eseguiti automaticamente)'
@'
Fase 1:
.\.venv\Scripts\python.exe .\uap_iw_phase1_discovery.py `
  --input .\aps.csv `
  --subnet 172.17.0.0/24 `
  --user ubnt `
  --password ubnt `
  --ssh-backend plink `
  --plink-path plink.exe `
  --accept-new-hostkeys `
  --out .\reports\report_subnet.csv `
  --json .\reports\report_subnet.json

Fase 2 dry-run:
.\.venv\Scripts\python.exe .\uap_iw_phase2_firmware_update.py `
  --input .\reports\report_subnet.json `
  --firmware .\firmware\BZ.qca933x.v4.3.28.11361.210128.2309.bin `
  --target-version-full 4.3.28.11361 `
  --target-version-short BZ.v4.3.28 `
  --user ubnt --password ubnt `
  --plink-path plink.exe --pscp-path pscp.exe `
  --out .\reports\phase2_update_report.csv `
  --json .\reports\phase2_update_report.json
'@ | Write-Host

Write-Host ''
Write-Host 'Nota: questo setup NON lancia discovery/upgrade/set-inform e NON modifica gli access point.'
