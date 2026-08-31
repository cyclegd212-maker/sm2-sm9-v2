param(
    [int]$Warmup = 1000,
    [int]$Iterations = 10000,
    [string]$GmSSLCommit = "24ae482701a7b124826c382fffc55c19f76d475d",
    [string]$Generator = "Ninja"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($Warmup -lt 1000) { throw "Submission warmup must be >= 1000" }
if ($Iterations -lt 10000) { throw "Submission iterations must be >= 10000" }

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $RepoRoot

function Invoke-Logged {
    param(
        [Parameter(Mandatory=$true)][string]$Log,
        [Parameter(Mandatory=$true)][scriptblock]$Command
    )
    & $Command 2>&1 | Tee-Object -FilePath $Log
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE. See $Log"
    }
}

function Find-BenchExe {
    $Candidates = @(
        (Join-Path $RepoRoot "native\build\Release\bench_v2.exe"),
        (Join-Path $RepoRoot "native\build\bench_v2.exe")
    )
    foreach ($Candidate in $Candidates) {
        if (Test-Path $Candidate) { return $Candidate }
    }
    throw "bench_v2.exe not found in expected build directories"
}

$V2Commit = (git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw "Unable to resolve V2 git commit" }
$GitStatus = git status --porcelain=v1
if ($LASTEXITCODE -ne 0) { throw "Unable to inspect git status" }
if ($GitStatus) {
    throw "Submission benchmark requires a clean working tree. Commit or stash changes first."
}

$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$RunId = "ryzen8845h-$Timestamp"
$EvidenceDir = Join-Path $RepoRoot "artifacts\submission-$RunId"
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

$DepsDir = Join-Path $RepoRoot "_deps"
$GmSSLDir = Join-Path $DepsDir "GmSSL"
$GmSSLBuild = Join-Path $GmSSLDir "build-v2-submission"
$GmSSLInstall = Join-Path $DepsDir "gmssl-install-submission"
$NativeBuild = Join-Path $RepoRoot "native\build"
$GmSSLBuildOptions = "-DENABLE_SM9=ON;-DENABLE_SM2_AMD64=OFF"

if (!(Test-Path $GmSSLDir)) {
    New-Item -ItemType Directory -Force -Path $DepsDir | Out-Null
    Invoke-Logged -Log (Join-Path $EvidenceDir "gmssl-clone.log") -Command {
        git clone https://github.com/guanzhi/GmSSL.git $GmSSLDir
    }
} else {
    Invoke-Logged -Log (Join-Path $EvidenceDir "gmssl-fetch.log") -Command {
        git -C $GmSSLDir fetch --all --tags --prune
    }
}

Invoke-Logged -Log (Join-Path $EvidenceDir "gmssl-checkout.log") -Command {
    git -C $GmSSLDir checkout --detach $GmSSLCommit
}
$ActualGmSSL = (git -C $GmSSLDir rev-parse HEAD).Trim()
if ($ActualGmSSL -ne $GmSSLCommit) {
    throw "GmSSL commit mismatch: expected $GmSSLCommit, got $ActualGmSSL"
}

if (Test-Path $GmSSLBuild) { Remove-Item -Recurse -Force $GmSSLBuild }
if (Test-Path $GmSSLInstall) { Remove-Item -Recurse -Force $GmSSLInstall }
if (Test-Path $NativeBuild) { Remove-Item -Recurse -Force $NativeBuild }

$GmSSLConfigureArgs = @(
    "-S", $GmSSLDir,
    "-B", $GmSSLBuild,
    "-G", $Generator,
    "-DCMAKE_BUILD_TYPE=Release",
    "-DENABLE_SM9=ON",
    "-DENABLE_SM2_AMD64=OFF",
    "-DCMAKE_INSTALL_PREFIX=$GmSSLInstall"
)
Invoke-Logged -Log (Join-Path $EvidenceDir "gmssl-configure.log") -Command {
    cmake @GmSSLConfigureArgs
}
Invoke-Logged -Log (Join-Path $EvidenceDir "gmssl-build.log") -Command {
    cmake --build $GmSSLBuild --config Release --parallel
}
Invoke-Logged -Log (Join-Path $EvidenceDir "upstream-tests.log") -Command {
    ctest --test-dir $GmSSLBuild -C Release -R '^(sm2_sign|sm3|sm3_hmac|sm9)$' --output-on-failure
}
Invoke-Logged -Log (Join-Path $EvidenceDir "gmssl-install.log") -Command {
    cmake --install $GmSSLBuild --config Release
}

$NativeConfigureArgs = @(
    "-S", (Join-Path $RepoRoot "native"),
    "-B", $NativeBuild,
    "-G", $Generator,
    "-DCMAKE_BUILD_TYPE=Release",
    "-DGMSSL_ROOT=$GmSSLInstall"
)
Invoke-Logged -Log (Join-Path $EvidenceDir "native-configure.log") -Command {
    cmake @NativeConfigureArgs
}
Invoke-Logged -Log (Join-Path $EvidenceDir "native-build.log") -Command {
    cmake --build $NativeBuild --config Release --parallel
}
Invoke-Logged -Log (Join-Path $EvidenceDir "native-tests.log") -Command {
    ctest --test-dir $NativeBuild -C Release --output-on-failure
}

python native/scripts/collect_env.py `
    --output (Join-Path $EvidenceDir "environment.json") `
    --run-id $RunId `
    --v2-commit $V2Commit `
    --gmssl-commit $GmSSLCommit `
    "--gmssl-build-options=$GmSSLBuildOptions" `
    --build-type Release `
    --warmup $Warmup `
    --iterations $Iterations | Tee-Object -FilePath (Join-Path $EvidenceDir "environment.log")
if ($LASTEXITCODE -ne 0) { throw "Environment collection failed" }

$BenchExe = Find-BenchExe
$Raw = Join-Path $EvidenceDir "raw.csv"
$Summary = Join-Path $EvidenceDir "summary.csv"
$BenchmarkLog = Join-Path $EvidenceDir "benchmark.log"
Remove-Item -ErrorAction SilentlyContinue $Raw, $Summary, $BenchmarkLog

foreach ($Size in 20,128,1024,4096) {
    "=== message_bytes=$Size ===" | Tee-Object -FilePath $BenchmarkLog -Append
    & $BenchExe `
        --run-id $RunId `
        --commit $V2Commit `
        --gmssl-commit $GmSSLCommit `
        --message-bytes $Size `
        --warmup $Warmup `
        --iterations $Iterations `
        --raw $Raw 2>&1 | Tee-Object -FilePath $BenchmarkLog -Append
    if ($LASTEXITCODE -ne 0) { throw "Benchmark failed at message size $Size" }
}

python -m native.bench.summarize $Raw $Summary | Tee-Object -FilePath (Join-Path $EvidenceDir "summary.log")
if ($LASTEXITCODE -ne 0) { throw "Summary generation failed" }
python -m native.bench.validate_evidence $Raw $Summary --sizes 20,128,1024,4096 --iterations $Iterations |
    Tee-Object -FilePath (Join-Path $EvidenceDir "evidence-validation.log")
if ($LASTEXITCODE -ne 0) { throw "Evidence validation failed" }

$Hashes = @{
    run_id = $RunId
    v2_commit = $V2Commit
    gmssl_commit = $GmSSLCommit
    gmssl_build_options = $GmSSLBuildOptions
    raw_sha256 = (Get-FileHash -Algorithm SHA256 $Raw).Hash.ToLowerInvariant()
    summary_sha256 = (Get-FileHash -Algorithm SHA256 $Summary).Hash.ToLowerInvariant()
}
$Hashes | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $EvidenceDir "hashes.json")

Write-Host "Submission benchmark evidence generated at: $EvidenceDir"
Write-Host "Do not copy values into the manuscript until this directory has been independently reviewed."
