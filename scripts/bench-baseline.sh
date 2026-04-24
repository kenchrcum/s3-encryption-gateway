#!/usr/bin/env bash
# V0.6-QA-1 Phase C — bench-baseline.
#
# Drives the micro-benchmark run documented in docs/plans/V0.6-QA-1-plan.md §3.1:
#
#   go test -run='^$' -bench='^Benchmark' -benchmem -benchtime=10s -count=10
#       -cpu=4 -timeout=30m ./internal/crypto/... ./internal/s3/...
#
# Writes a provenance header (Go version, runner, commit SHA, GOOS/GOARCH)
# followed by the raw `go test` output so the file is both human-readable
# and directly consumable by benchstat.
#
# Usage:
#   scripts/bench-baseline.sh [OUTPUT_FILE]
#
# OUTPUT_FILE defaults to docs/perf/v0.6-qa-1/micro-baseline.txt. Pass
# /dev/stdout to dump to the terminal (useful for the PR advisory path
# which diffs /tmp/… against the committed baseline).
#
# Environment overrides (for the PR advisory short-run variant — §3.3 of the plan):
#   BENCH_TIME    default 10s  (3s for advisory)
#   BENCH_COUNT   default 10   (3 for advisory)
#   BENCH_CPU     default 4
#   BENCH_TIMEOUT default 30m

set -euo pipefail

cd "$(dirname "$0")/.."

out="${1:-docs/perf/v0.6-qa-1/micro-baseline.txt}"
bench_time="${BENCH_TIME:-10s}"
bench_count="${BENCH_COUNT:-10}"
bench_cpu="${BENCH_CPU:-4}"
bench_timeout="${BENCH_TIMEOUT:-30m}"

mkdir -p "$(dirname "$out")"

# Provenance header — committed alongside the numbers so future readers
# (and the nightly comparator) can tell *what runner class* produced them.
# See plan §3.1 noise-discipline requirements.
commit="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
{
  printf '# V0.6-QA-1 micro-benchmark baseline — do not hand-edit\n'
  printf '# generated_at: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '# commit: %s\n' "$commit"
  printf '# go_version: %s\n' "$(go version | awk '{print $3}')"
  printf '# goos: %s\n' "$(go env GOOS)"
  printf '# goarch: %s\n' "$(go env GOARCH)"
  printf '# bench_time: %s  bench_count: %s  bench_cpu: %s\n' "$bench_time" "$bench_count" "$bench_cpu"
  printf '#\n'
} >"$out"

printf 'bench-baseline: running micro benchmarks → %s\n' "$out" >&2
printf 'bench-baseline: count=%s time=%s cpu=%s timeout=%s\n' \
  "$bench_count" "$bench_time" "$bench_cpu" "$bench_timeout" >&2

go test \
  -run='^$' \
  -bench='^Benchmark' \
  -benchmem \
  -benchtime="$bench_time" \
  -count="$bench_count" \
  -cpu="$bench_cpu" \
  -timeout="$bench_timeout" \
  ./internal/crypto/... ./internal/s3/... \
  >>"$out"

printf 'bench-baseline: done.\n' >&2
