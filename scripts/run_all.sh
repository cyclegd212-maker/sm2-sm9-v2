#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python bench/collect_env.py | tee logs/environment.log
for size in 20 128 1024 4096; do
  python -m bench.benchmark --warmup 100 --iterations 1000 --message-bytes "$size" | tee "logs/bench_${size}.log"
done
