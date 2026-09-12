param(
    [Parameter(Mandatory = $true)]
    [string]$GmsslRoot,

    [string]$V2Raw = "",

    [ValidateRange(1, 10000000)]
    [int]$Warmup = 1000,

    [ValidateRange(1, 10000000)]
    [int]$Iterations = 1000,

    [string]$GmsslCommit = "24ae482701a7b124826c382fffc55c19f76d475d"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Invoke-NativeLogged {
    param(
        [Parameter(Mandatory = $true)] [string]$Log,
        [Parameter(Mandatory = $true)] [string]$Command,
        [Parameter(Mandatory = $true)] [string[]]$Arguments
    )
    & $Command @Arguments 2>&1 | Tee-Object -FilePath $Log -Append
    if ($LASTEXITCODE -ne 0) {
        throw "native command failed ($LASTEXITCODE): $Command $($Arguments -join ' ')"
    }
}

function Command-Text {
    param([string]$Command, [string[]]$Arguments)
    try {
        return ((& $Command @Arguments 2>&1) -join "`n")
    }
    catch {
        return "UNAVAILABLE: $($_.Exception.Message)"
    }
}

$ResolvedGmsslRoot = (Resolve-Path $GmsslRoot).Path
if (-not (Test-Path (Join-Path $ResolvedGmsslRoot "include\gmssl\sm2.h"))) {
    throw "GmSSL headers not found below $ResolvedGmsslRoot"
}
if (-not (Test-Path (Join-Path $ResolvedGmsslRoot "include\gmssl\sm2_z256.h"))) {
    throw "GmSSL low-level SM2 header not found below $ResolvedGmsslRoot"
}

$GitHead = (git rev-parse HEAD 2>$null).Trim()
if ($LASTEXITCODE -ne 0 -or -not $GitHead) {
    throw "this formal benchmark must run from a Git checkout so the PCHS source commit is traceable"
}
$GitStatus = (git status --porcelain=v1 2>$null) -join "`n"
if ($LASTEXITCODE -ne 0) {
    throw "unable to obtain git status"
}
if ($GitStatus) {
    throw "working tree is not clean; commit/stash changes before the formal benchmark"
}

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$RunId = "pchs-liu2018-ryzen8845h-$Timestamp"
$ArtifactDir = Join-Path $Root "artifacts\$RunId"
$BuildDir = Join-Path $Root "native\build-pchs-liu2018"
New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null

$Raw = Join-Path $ArtifactDir "raw.csv"
$Summary = Join-Path $ArtifactDir "summary.csv"
$Environment = Join-Path $ArtifactDir "environment.json"
$BuildLog = Join-Path $ArtifactDir "build.log"
$TestLog = Join-Path $ArtifactDir "test.log"
$BenchmarkLog = Join-Path $ArtifactDir "benchmark.log"
$Comparison = Join-Path $ArtifactDir "comparison.csv"

if (Test-Path $Raw) {
    throw "refusing to overwrite existing raw CSV: $Raw"
}

$ConfigureArgs = @(
    "-S", "native",
    "-B", $BuildDir,
    "-G", "Ninja",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DGMSSL_ROOT=$ResolvedGmsslRoot"
)
Invoke-NativeLogged -Log $BuildLog -Command "cmake" -Arguments $ConfigureArgs

$BuildArgs = @("--build", $BuildDir, "--config", "Release")
Invoke-NativeLogged -Log $BuildLog -Command "cmake" -Arguments $BuildArgs

$TestArgs = @("--test-dir", $BuildDir, "-C", "Release", "--output-on-failure")
Invoke-NativeLogged -Log $TestLog -Command "ctest" -Arguments $TestArgs

$BenchExe = Get-ChildItem -Path $BuildDir -Recurse -File -Filter "bench_pchs_liu2018.exe" |
    Select-Object -First 1
if (-not $BenchExe) {
    throw "bench_pchs_liu2018.exe not found below $BuildDir"
}

foreach ($Size in 20, 128, 1024, 4096) {
    $BenchArgs = @(
        "--run-id", $RunId,
        "--commit", $GitHead,
        "--gmssl-commit", $GmsslCommit,
        "--message-bytes", [string]$Size,
        "--warmup", [string]$Warmup,
        "--iterations", [string]$Iterations,
        "--raw", $Raw
    )
    Invoke-NativeLogged -Log $BenchmarkLog -Command $BenchExe.FullName -Arguments $BenchArgs
}

$SummaryArgs = @(
    "scripts/summarize_pchs_liu2018.py",
    "--raw", $Raw,
    "--out", $Summary,
    "--expected-sizes", "20,128,1024,4096",
    "--expected-n", [string]$Iterations
)
Invoke-NativeLogged -Log $BenchmarkLog -Command "python" -Arguments $SummaryArgs

$Cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$Os = Get-CimInstance Win32_OperatingSystem
$EnvRecord = [ordered]@{
    run_id = $RunId
    pchs_commit = $GitHead
    gmssl_commit = $GmsslCommit
    gmssl_root = $ResolvedGmsslRoot
    build_type = "Release"
    generator = "Ninja"
    warmup = $Warmup
    iterations = $Iterations
    message_bytes = @(20, 128, 1024, 4096)
    expected_phases = @("pchs_sender_signcrypt", "pchs_unsigncrypt")
    platform = "Windows"
    os_caption = $Os.Caption
    os_version = $Os.Version
    cpu_model = $Cpu.Name
    logical_processors = $Cpu.NumberOfLogicalProcessors
    cmake = Command-Text "cmake" @("--version")
    ninja = Command-Text "ninja" @("--version")
    compiler_cc = Command-Text "cc" @("--version")
    python = Command-Text "python" @("--version")
    git_status_porcelain_before_run = $GitStatus
    benchmark_executable = $BenchExe.FullName
    raw_csv = $Raw
    summary_csv = $Summary
    created_local = (Get-Date).ToString("o")
}
$EnvRecord | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $Environment

if ($V2Raw) {
    $ResolvedV2Raw = (Resolve-Path $V2Raw).Path
    $CompareArgs = @(
        "scripts/compare_v2_pchs.py",
        "--v2-raw", $ResolvedV2Raw,
        "--pchs-raw", $Raw,
        "--out", $Comparison,
        "--expected-sizes", "20,128,1024,4096",
        "--expected-n", [string]$Iterations
    )
    Invoke-NativeLogged -Log $BenchmarkLog -Command "python" -Arguments $CompareArgs
}

Write-Host "PCHS formal benchmark complete"
Write-Host "Run ID: $RunId"
Write-Host "Artifact directory: $ArtifactDir"
Write-Host "Raw samples: $Raw"
Write-Host "Summary: $Summary"
if ($V2Raw) {
    Write-Host "V2/PCHS comparison: $Comparison"
}
