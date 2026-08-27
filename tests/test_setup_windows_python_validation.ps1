$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path $PSScriptRoot -Parent
$setupPath = Join-Path $repoRoot 'setup_windows.ps1'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERT TRUE FAILED: $Message" }
}

function Assert-False([bool]$Condition, [string]$Message) {
    if ($Condition) { throw "ASSERT FALSE FAILED: $Message" }
}

function Assert-Equal($Expected, $Actual, [string]$Message) {
    if ($Expected -ne $Actual) {
        throw "ASSERT EQUAL FAILED: $Message (expected=$Expected actual=$Actual)"
    }
}

function Write-CmdShim([string]$Path, [string[]]$Lines) {
    Set-Content -LiteralPath $Path -Value $Lines -Encoding ASCII -Force
}

function Compile-TestLauncher([string]$OutputPath, [bool]$CreateValidVenv) {
    $className = if ($CreateValidVenv) { 'UnifiPythonValidTestLauncher' } else { 'UnifiPythonInvalidTestLauncher' }
    $createBody = if ($CreateValidVenv) {
        'File.Copy(Process.GetCurrentProcess().MainModule.FileName, target, true);'
    } else {
        'File.WriteAllText(target, "not a Windows executable");'
    }
    $source = @"
using System;
using System.Diagnostics;
using System.IO;

public static class $className {
    public static int Main(string[] args) {
        if (args.Length >= 2 && args[0] == "-c") {
            Console.WriteLine("launcher noise stdout");
            Console.Error.WriteLine("launcher noise stderr");
            Console.WriteLine("__UNIFI_PYTHON_OK__");
            return 0;
        }
        if (args.Length >= 3 && args[0] == "-m" && args[1] == "venv") {
            string scripts = Path.Combine(Path.GetFullPath(args[2]), "Scripts");
            Directory.CreateDirectory(scripts);
            string target = Path.Combine(scripts, "python.exe");
            $createBody
            return 0;
        }
        if (args.Length == 1 && args[0] == "--version") {
            Console.WriteLine("Python test launcher");
            return 0;
        }
        return 2;
    }
}
"@
    $sourcePath = [System.IO.Path]::ChangeExtension($OutputPath, '.cs')
    Set-Content -LiteralPath $sourcePath -Value $source -Encoding UTF8
    $cscCandidates = @(
        (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
        (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
    )
    $csc = $cscCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $csc) { throw 'Windows C# compiler not found for isolated launcher fixtures.' }
    try {
        $compilerOutput = @(& $csc /nologo /target:exe "/out:$OutputPath" $sourcePath 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw ('Test launcher compilation failed: ' + ($compilerOutput -join '; '))
        }
    } finally {
        Remove-Item -LiteralPath $sourcePath -Force -ErrorAction SilentlyContinue
    }
}

. $setupPath -FunctionsOnly

$productionFunctions = @(
    'Test-PythonLauncher',
    'Resolve-PythonCommand',
    'Assert-ValidPythonLauncher',
    'Get-VenvState',
    'Initialize-PythonEnvironment'
)
foreach ($name in $productionFunctions) {
    $command = Get-Command $name -CommandType Function -ErrorAction Stop
    Assert-Equal ([System.IO.Path]::GetFullPath($setupPath)) ([System.IO.Path]::GetFullPath($command.ScriptBlock.File)) "$name must come from setup_windows.ps1"
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("unifi-setup-python-test-" + [guid]::NewGuid().ToString('N'))
$originalPath = $env:Path
$originalLocation = (Get-Location).Path

try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    $launcherDir = Join-Path $testRoot 'launchers'
    $shimDir = Join-Path $testRoot 'path-shims'
    New-Item -ItemType Directory -Path $launcherDir, $shimDir | Out-Null

    $validLauncher = Join-Path $launcherDir 'valid-python.exe'
    $invalidVenvBuilder = Join-Path $launcherDir 'invalid-venv-builder.exe'
    Compile-TestLauncher -OutputPath $validLauncher -CreateValidVenv $true
    Compile-TestLauncher -OutputPath $invalidVenvBuilder -CreateValidVenv $false

    Assert-True (Test-PythonLauncher -Launcher $validLauncher) 'valid exact-path launcher must pass'
    $boolOutput = @(Test-PythonLauncher -Launcher $validLauncher)
    Assert-Equal 1 $boolOutput.Count 'launcher validation must emit exactly one value'
    Assert-True ($boolOutput[0] -is [bool]) 'launcher validation output must be Boolean'

    $bogusExitZero = Join-Path $shimDir 'bogus.cmd'
    Write-CmdShim $bogusExitZero @('@echo bogus output', '@exit /b 0')
    Assert-False (Test-PythonLauncher -Launcher $bogusExitZero) 'exit zero without sentinel must fail'

    $pyShim = Join-Path $shimDir 'py.cmd'
    $pythonShim = Join-Path $shimDir 'python.cmd'
    $env:Path = $shimDir

    Write-CmdShim $pyShim @("@`"$validLauncher`" %*", '@exit /b %errorlevel%')
    Write-CmdShim $pythonShim @('@exit /b 1')
    $resolved = @(Resolve-PythonCommand)
    Assert-Equal 1 $resolved.Count 'noisy valid py must not contaminate resolver output'
    Assert-Equal 'py' $resolved[0] 'valid PATH py must be preferred'

    Write-CmdShim $pyShim @('@echo broken py', '@exit /b 1')
    Write-CmdShim $pythonShim @("@`"$validLauncher`" %*", '@exit /b %errorlevel%')
    Assert-Equal 'python' (Resolve-PythonCommand) 'broken py must be ignored and valid python accepted'

    Write-CmdShim $pythonShim @('@echo broken python', '@exit /b 1')
    Assert-Equal $null (Resolve-PythonCommand) 'broken py and python must both be ignored'

    Write-CmdShim $pyShim @('@echo bogus py without sentinel', '@exit /b 0')
    Write-CmdShim $pythonShim @("@`"$validLauncher`" %*", '@exit /b %errorlevel%')
    Assert-Equal 'python' (Resolve-PythonCommand) 'bogus exit-zero py without sentinel must be ignored'

    $env:Path = $originalPath

    $validRoot = Join-Path $testRoot 'valid-venv'
    $validScripts = Join-Path $validRoot '.venv\Scripts'
    New-Item -ItemType Directory -Path $validScripts | Out-Null
    Copy-Item -LiteralPath $validLauncher -Destination (Join-Path $validScripts 'python.exe')
    Set-Content -LiteralPath (Join-Path $validRoot '.venv\keep.marker') -Value 'keep'
    Assert-Equal 'VALID' (Get-VenvState -ProjectRoot $validRoot) 'working venv must be valid'
    $validResult = Initialize-PythonEnvironment -ProjectRoot $validRoot -PythonLauncher $validLauncher -UsingPythonEmbed $false
    Assert-True $validResult.UseVenv 'valid venv must be reused'
    Assert-False $validResult.Rebuilt 'valid venv must not be rebuilt'
    Assert-True (Test-Path -LiteralPath (Join-Path $validRoot '.venv\keep.marker')) 'valid venv must not be deleted'

    $missingRoot = Join-Path $testRoot 'missing-python-venv'
    New-Item -ItemType Directory -Path (Join-Path $missingRoot '.venv') | Out-Null
    Assert-Equal 'BROKEN' (Get-VenvState -ProjectRoot $missingRoot) 'venv missing Scripts/python.exe must be broken'

    $brokenRoot = Join-Path $testRoot 'broken-launcher-venv'
    $brokenScripts = Join-Path $brokenRoot '.venv\Scripts'
    New-Item -ItemType Directory -Path $brokenScripts | Out-Null
    Set-Content -LiteralPath (Join-Path $brokenScripts 'python.exe') -Value 'broken executable'
    Set-Content -LiteralPath (Join-Path $brokenRoot '.venv\stale.marker') -Value 'stale'
    Assert-Equal 'BROKEN' (Get-VenvState -ProjectRoot $brokenRoot) 'non-executable venv launcher must be broken'
    $rebuilt = Initialize-PythonEnvironment -ProjectRoot $brokenRoot -PythonLauncher $validLauncher -UsingPythonEmbed $false
    Assert-True $rebuilt.Rebuilt 'broken venv must be rebuilt with normal Python'
    Assert-Equal 'VALID' (Get-VenvState -ProjectRoot $brokenRoot) 'rebuilt interpreter must validate'
    Assert-False (Test-Path -LiteralPath (Join-Path $brokenRoot '.venv\stale.marker')) 'old broken venv must be removed'

    $absentRoot = Join-Path $testRoot 'absent-normal'
    New-Item -ItemType Directory -Path $absentRoot | Out-Null
    Assert-Equal 'ABSENT' (Get-VenvState -ProjectRoot $absentRoot) 'missing venv must be absent'
    $created = Initialize-PythonEnvironment -ProjectRoot $absentRoot -PythonLauncher $validLauncher -UsingPythonEmbed $false
    Assert-Equal 'ABSENT' $created.InitialVenvState 'normal mode must see absent state'
    Assert-Equal 'VALID' (Get-VenvState -ProjectRoot $absentRoot) 'normal mode must create and validate venv'

    $invalidRoot = Join-Path $testRoot 'invalid-rebuild'
    New-Item -ItemType Directory -Path (Join-Path $invalidRoot '.venv') | Out-Null
    $invalidFailed = $false
    try {
        Initialize-PythonEnvironment -ProjectRoot $invalidRoot -PythonLauncher $invalidVenvBuilder -UsingPythonEmbed $false | Out-Null
    } catch {
        $invalidFailed = $_.Exception.Message -match 'nuovo interprete non è eseguibile'
    }
    Assert-True $invalidFailed 'invalid recreated interpreter must fail clearly'

    $embeddedBrokenRoot = Join-Path $testRoot 'embedded-broken'
    $embeddedScripts = Join-Path $embeddedBrokenRoot '.venv\Scripts'
    New-Item -ItemType Directory -Path $embeddedScripts | Out-Null
    Set-Content -LiteralPath (Join-Path $embeddedScripts 'python.exe') -Value 'broken executable'
    $embeddedMarker = Join-Path $embeddedBrokenRoot '.venv\untouched.marker'
    Set-Content -LiteralPath $embeddedMarker -Value 'keep'
    $embeddedResult = Initialize-PythonEnvironment -ProjectRoot $embeddedBrokenRoot -PythonLauncher $validLauncher -UsingPythonEmbed $true
    Assert-False $embeddedResult.UseVenv 'embedded mode must bypass broken venv'
    Assert-Equal $validLauncher $embeddedResult.PythonForInstall 'embedded mode must select exact embedded launcher'
    Assert-True (Test-Path -LiteralPath $embeddedMarker) 'embedded mode must not delete broken venv'

    $embeddedAbsentRoot = Join-Path $testRoot 'embedded-absent'
    New-Item -ItemType Directory -Path $embeddedAbsentRoot | Out-Null
    $embeddedAbsent = Initialize-PythonEnvironment -ProjectRoot $embeddedAbsentRoot -PythonLauncher $validLauncher -UsingPythonEmbed $true
    Assert-False $embeddedAbsent.UseVenv 'embedded mode must not create a venv'
    Assert-False (Test-Path -LiteralPath (Join-Path $embeddedAbsentRoot '.venv')) 'embedded absent state must remain absent'

    $setupTokens = $null
    $setupErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($setupPath, [ref]$setupTokens, [ref]$setupErrors) | Out-Null
    Assert-Equal 0 $setupErrors.Count 'setup_windows.ps1 parser validation'

    $testTokens = $null
    $testErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$testTokens, [ref]$testErrors) | Out-Null
    Assert-Equal 0 $testErrors.Count 'test script parser validation'

    $versionOutput = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $setupPath -Version 2>&1)
    Assert-Equal 0 $LASTEXITCODE 'setup -Version must exit zero'
    Assert-True (($versionOutput -join "`n") -match 'Version:\s+0\.5\.1') 'setup -Version must report 0.5.1'

    Write-Host 'PASS: setup_windows Python launcher and virtualenv regression tests'
} finally {
    $env:Path = $originalPath
    Set-Location -LiteralPath $originalLocation
    if (Test-Path -LiteralPath $testRoot) {
        for ($attempt = 1; $attempt -le 20; $attempt++) {
            try {
                Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction Stop
                break
            } catch {
                if ($attempt -eq 20) { throw }
                Start-Sleep -Milliseconds 100
            }
        }
    }
}
