$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repoOwner = 'emanuelebruno'
$repoName = 'unifi-massive-adoption-update'
$refsToTry = @('main', 'master')
$rawBase = "https://raw.githubusercontent.com/$repoOwner/$repoName"
$downloadsDir = '.\downloads'
$puttyToolsDir = '.\tools\putty'

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

function Ensure-Directory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Ensure-TlsForDownloads {
    try {
        $protocol = [Net.SecurityProtocolType]::Tls12
        try {
            $tls13 = [Net.SecurityProtocolType]::Tls13
            $protocol = $protocol -bor $tls13
        } catch {
        }
        [Net.ServicePointManager]::SecurityProtocol = $protocol
    } catch {
    }
}

function Download-Url {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    Ensure-TlsForDownloads

    $destinationDir = Split-Path -Parent $DestinationPath
    if ($destinationDir) { Ensure-Directory -Path $destinationDir }
    Ensure-Directory -Path $downloadsDir

    Write-Host ("Download: {0}" -f $Url)
    Write-Host ("      -> {0}" -f $DestinationPath)

    if (Test-Path -LiteralPath $DestinationPath) {
        Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
    }

    $hasBits = $false
    if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) { $hasBits = $true }

    if ($hasBits) {
        try {
            Start-BitsTransfer -Source $Url -Destination $DestinationPath -ErrorAction Stop
        } catch {
            if (Test-Path -LiteralPath $DestinationPath) {
                Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
            }
            $hasBits = $false
        }
    }

    if (-not $hasBits) {
        $iwrParams = @{ Uri = $Url; OutFile = $DestinationPath; ErrorAction = 'Stop' }
        if ($PSVersionTable.PSVersion.Major -lt 6) { $iwrParams.UseBasicParsing = $true }
        Invoke-WebRequest @iwrParams
    }

    if (-not (Test-Path -LiteralPath $DestinationPath)) { return $false }
    $item = Get-Item -LiteralPath $DestinationPath -ErrorAction SilentlyContinue
    if (-not $item -or $item.Length -le 0) { return $false }
    return $true
}

function Download-GitHubRelative {
    param(
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    foreach ($ref in $refsToTry) {
        $url = "$rawBase/$ref/$RelativePath"
        try {
            $ok = Download-Url -Url $url -DestinationPath $DestinationPath
            if ($ok) { return $true }
        } catch {
            if (Test-Path -LiteralPath $DestinationPath) {
                Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
            }
        }
    }
    return $false
}

function Try-Install-WithWinget {
    param([Parameter(Mandatory = $true)][string]$PackageId)
    $winget = Get-CommandPathOrNull -CommandName 'winget'
    if (-not $winget) {
        Write-Host "WARNING: winget non disponibile, uso installer diretto."
        return $false
    }

    & winget install $PackageId --silent --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) {
        Write-Host ("WARNING: winget install {0} fallito (exit code: {1}), uso installer diretto." -f $PackageId, $LASTEXITCODE)
        return $false
    }

    return $true
}

function Resolve-PythonCommand {
    $py = Get-CommandPathOrNull -CommandName 'py'
    if ($py) { return 'py' }
    $python = Get-CommandPathOrNull -CommandName 'python'
    if ($python) { return 'python' }
    return $null
}

function Add-ToSessionPath([string]$Dir) {
    if (-not $Dir) { return }
    if (-not (Test-Path -LiteralPath $Dir)) { return }
    $pathParts = $env:Path -split ';'
    foreach ($p in $pathParts) {
        if ($p.TrimEnd('\') -ieq $Dir.TrimEnd('\')) { return }
    }
    $env:Path = ($Dir.TrimEnd('\') + ';' + $env:Path)
}

function Find-UserPythonExe {
    $base = Join-Path $env:LocalAppData 'Programs\Python'
    if (-not (Test-Path -LiteralPath $base)) { return $null }

    $dirs = Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue
    $candidates = @()
    foreach ($d in $dirs) {
        $exe = Join-Path $d.FullName 'python.exe'
        if (Test-Path -LiteralPath $exe) {
            $candidates += $exe
        }
    }

    if ($candidates.Count -eq 0) { return $null }

    $scored = foreach ($c in $candidates) {
        $dirName = Split-Path (Split-Path $c -Parent) -Leaf
        $score = 0
        if ($dirName -match '^Python(\d+)$') { $score = [int]$Matches[1] }
        [PSCustomObject]@{ Path = $c; Score = $score }
    }

    return ($scored | Sort-Object -Property Score -Descending | Select-Object -First 1).Path
}

function Ensure-Python {
    $pythonCmd = Resolve-PythonCommand
    if ($pythonCmd) { return $pythonCmd }

    $installed = Try-Install-WithWinget -PackageId 'Python.Python.3.12'
    if ($installed) {
        $pythonCmd = Resolve-PythonCommand
        if ($pythonCmd) { return $pythonCmd }
    }

    Ensure-Directory -Path $downloadsDir
    $installerPath = Join-Path $downloadsDir 'python-installer.exe'

    $pythonVersionsToTry = @('3.12.9', '3.12.8', '3.12.7', '3.12.6')
    $downloaded = $false
    foreach ($v in $pythonVersionsToTry) {
        $url = "https://www.python.org/ftp/python/$v/python-$v-amd64.exe"
        try {
            $downloaded = Download-Url -Url $url -DestinationPath $installerPath
            if ($downloaded) { break }
        } catch {
        }
    }

    if (-not $downloaded) {
        throw 'Impossibile scaricare l’installer Python da python.org.'
    }

    Write-Host ("Esecuzione installer: {0}" -f $installerPath)
    $p = Start-Process -FilePath $installerPath -ArgumentList '/quiet InstallAllUsers=0 PrependPath=1 Include_pip=1 Include_launcher=1' -Wait -PassThru
    if (($p.ExitCode -ne 0) -and ($p.ExitCode -ne 3010)) {
        throw "Installazione Python fallita (exit code: $($p.ExitCode))."
    }

    $pythonExe = Find-UserPythonExe
    if ($pythonExe) {
        $pythonDir = Split-Path $pythonExe -Parent
        Add-ToSessionPath -Dir $pythonDir
        Add-ToSessionPath -Dir (Join-Path $pythonDir 'Scripts')
        return $pythonExe
    }

    $pythonCmd = Resolve-PythonCommand
    if ($pythonCmd) { return $pythonCmd }
    throw 'Python installato ma non rilevabile (PATH non aggiornato e python.exe non trovato in LocalAppData).'
}

function Resolve-PuttyPaths {
    $plink = Get-CommandPathOrNull -CommandName 'plink.exe'
    $pscp = Get-CommandPathOrNull -CommandName 'pscp.exe'
    if ($plink -and $pscp) {
        return @{ Plink = $plink; Pscp = $pscp }
    }

    $pfPlink = 'C:\Program Files\PuTTY\plink.exe'
    $pfPscp = 'C:\Program Files\PuTTY\pscp.exe'
    if ((Test-Path -LiteralPath $pfPlink) -and (Test-Path -LiteralPath $pfPscp)) {
        return @{ Plink = $pfPlink; Pscp = $pfPscp }
    }

    $localPlink = Join-Path $puttyToolsDir 'plink.exe'
    $localPscp = Join-Path $puttyToolsDir 'pscp.exe'
    if ((Test-Path -LiteralPath $localPlink) -and (Test-Path -LiteralPath $localPscp)) {
        return @{ Plink = $localPlink; Pscp = $localPscp }
    }

    return $null
}

function Ensure-Putty {
    $resolved = Resolve-PuttyPaths
    if ($resolved) {
        $script:PlinkPath = $resolved.Plink
        $script:PscpPath = $resolved.Pscp
        return
    }

    $installed = Try-Install-WithWinget -PackageId 'PuTTY.PuTTY'
    if ($installed) {
        $resolved = Resolve-PuttyPaths
        if ($resolved) {
            $script:PlinkPath = $resolved.Plink
            $script:PscpPath = $resolved.Pscp
            return
        }
    }

    Ensure-Directory -Path $downloadsDir
    $msiPath = Join-Path $downloadsDir 'putty-installer.msi'

    $puttyMsiUrls = @(
        'https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-0.83-installer.msi',
        'https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-0.82-installer.msi',
        'https://the.earth.li/~sgtatham/putty/0.83/w64/putty-64bit-0.83-installer.msi',
        'https://the.earth.li/~sgtatham/putty/0.82/w64/putty-64bit-0.82-installer.msi'
    )

    $downloaded = $false
    foreach ($u in $puttyMsiUrls) {
        try {
            $downloaded = Download-Url -Url $u -DestinationPath $msiPath
            if ($downloaded) { break }
        } catch {
        }
    }

    if ($downloaded) {
        Write-Host ("Installazione MSI: {0}" -f $msiPath)
        $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList "/i `"$msiPath`" /qn" -Wait -PassThru
        if (($proc.ExitCode -eq 0) -or ($proc.ExitCode -eq 3010)) {
            $resolved = Resolve-PuttyPaths
            if ($resolved) {
                $script:PlinkPath = $resolved.Plink
                $script:PscpPath = $resolved.Pscp
                $pfDir = Split-Path $script:PlinkPath -Parent
                Add-ToSessionPath -Dir $pfDir
                return
            }
        } else {
            Write-Host ("WARNING: installazione PuTTY MSI fallita (exit code: {0}). Provo fallback standalone." -f $proc.ExitCode)
        }
    } else {
        Write-Host 'WARNING: impossibile scaricare PuTTY MSI. Provo fallback standalone.'
    }

    Ensure-Directory -Path $puttyToolsDir
    $plinkLocal = Join-Path $puttyToolsDir 'plink.exe'
    $pscpLocal = Join-Path $puttyToolsDir 'pscp.exe'

    $plinkUrl = 'https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe'
    $pscpUrl = 'https://the.earth.li/~sgtatham/putty/latest/w64/pscp.exe'

    $okPlink = Download-Url -Url $plinkUrl -DestinationPath $plinkLocal
    $okPscp = Download-Url -Url $pscpUrl -DestinationPath $pscpLocal
    if (-not $okPlink -or -not $okPscp) {
        throw 'Installazione PuTTY fallita: plink.exe/pscp.exe non disponibili (né winget, né MSI, né standalone).'
    }

    $script:PlinkPath = $plinkLocal
    $script:PscpPath = $pscpLocal
}

function Quote-Arg([string]$Value) {
    if (-not $Value) { return $Value }
    if ($Value -match '\s') { return ('"{0}"' -f $Value) }
    return $Value
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
        $ok = Download-GitHubRelative -RelativePath $file -DestinationPath ".\$file"
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
    $ok = Download-GitHubRelative -RelativePath $firmwareRel -DestinationPath $firmwareLocal
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
Write-Host ('plink: ' + $script:PlinkPath)
Write-Host ('pscp:  ' + $script:PscpPath)

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
$plinkForPrint = Quote-Arg $script:PlinkPath
$pscpForPrint = Quote-Arg $script:PscpPath

@"
Fase 1:
.\.venv\Scripts\python.exe .\uap_iw_phase1_discovery.py `
  --input .\aps.csv `
  --subnet 172.17.0.0/24 `
  --user ubnt `
  --password ubnt `
  --ssh-backend plink `
  --plink-path $plinkForPrint `
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
  --plink-path $plinkForPrint --pscp-path $pscpForPrint `
  --out .\reports\phase2_update_report.csv `
  --json .\reports\phase2_update_report.json
"@ | Write-Host

Write-Host ''
Write-Host 'Nota: questo setup NON lancia discovery/upgrade/set-inform e NON modifica gli access point.'
