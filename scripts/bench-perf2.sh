#!/usr/bin/env bash
# V0.6-PERF-2 Phase A — Capture baseline benchmark results (before the custom retryer).
# Run this BEFORE merging Phase C / Phase D changes.
#
# Usage: ./scripts/bench-perf2.sh
#
# Output: docs/perf/v0.6-perf-2-baseline.txt
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT="${REPO_ROOT}/docs/perf/v0.6-perf-2-baseline.txt"

mkdir -p "${REPO_ROOT}/docs/perf"

echo "Capturing V0.6-PERF-2 baseline benchmarks…"
echo "Output: ${OUT}"
echo ""

cd "${REPO_ROOT}"
go test \
  -run='^$' \
  -bench='BenchmarkS3Client_' \
  -benchmem \
  -benchtime=10s \
  -count=5 \
  ./internal/s3/ \
  | tee "${OUT}"

echo ""
echo "Baseline captured to ${OUT}"
echo "Run scripts/bench-perf2-after.sh after Phase D lands to compute the delta."
