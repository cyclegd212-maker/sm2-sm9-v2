$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
New-Item -ItemType Directory -Force -Path logs, data/raw, data/processed | Out-Null
Remove-Item -ErrorAction SilentlyContinue data/raw/timings.csv, data/processed/summary.csv
python bench/collect_env.py | Tee-Object -FilePath logs/environment.log
foreach ($size in 20,128,1024,4096) {
  python -m bench.benchmark --warmup 100 --iterations 1000 --message-bytes $size | Tee-Object -FilePath "logs/bench_$size.log"
}
