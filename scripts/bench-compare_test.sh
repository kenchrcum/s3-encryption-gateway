#!/usr/bin/env bash
# V0.6-QA-1 Phase D — bench-compare self-test.
#
# Lightweight pure-bash tests for scripts/bench-compare.sh macro mode
# (§7.3 of the plan). Micro-mode tests are omitted here because they require
# a benchstat install and golden input fixtures that would balloon the
# commit; the GitHub Actions job installs benchstat and runs a live round
# trip against the committed baseline.
#
# Usage:
#   scripts/bench-compare_test.sh
#
# Exit codes: 0 = all pass, 1 = one or more tests failed.

set -euo pipefail

cd "$(dirname "$0")/.."

script="scripts/bench-compare.sh"
if [[ ! -x "$script" ]]; then
  echo "bench-compare_test: $script not executable" >&2
  exit 2
fi

tmp="$(mktemp -d -t qa1-bc-test.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

assert_exit() {
  local want="$1"; shift
  local name="$1"; shift
  local got
  set +e
  "$@" >/dev/null 2>&1
  got=$?
  set -e
  if [[ "$got" == "$want" ]]; then
    printf 'PASS  %s\n' "$name"
    pass=$((pass + 1))
  else
    printf 'FAIL  %s (want exit=%s, got=%s)\n' "$name" "$want" "$got"
    fail=$((fail + 1))
  fi
}

# --- fixtures --------------------------------------------------------------
cat >"$tmp/base.json" <<EOF
{
  "schema_version": "1",
  "provider": "minio",
  "runs": [
    {"test":"Load_RangeRead","throughput_mbps":100,"latency_ns":{"p50":1000,"p95":2000,"p99":3000},"errors":0,"retries_total":0,"heap_inuse_max_bytes":1048576},
    {"test":"Load_Multipart","throughput_mbps":80,"latency_ns":{"p50":5000,"p95":8000,"p99":12000},"errors":0,"retries_total":0,"heap_inuse_max_bytes":2097152}
  ]
}
EOF

cat >"$tmp/same.json" <<EOF
{
  "schema_version": "1",
  "provider": "minio",
  "runs": [
    {"test":"Load_RangeRead","throughput_mbps":100,"latency_ns":{"p50":1000,"p95":2000,"p99":3000},"errors":0,"retries_total":0,"heap_inuse_max_bytes":1048576},
    {"test":"Load_Multipart","throughput_mbps":80,"latency_ns":{"p50":5000,"p95":8000,"p99":12000},"errors":0,"retries_total":0,"heap_inuse_max_bytes":2097152}
  ]
}
EOF

cat >"$tmp/throughput_drop.json" <<EOF
{
  "schema_version": "1",
  "provider": "minio",
  "runs": [
    {"test":"Load_RangeRead","throughput_mbps":80,"latency_ns":{"p50":1000,"p95":2000,"p99":3000},"errors":0,"retries_total":0,"heap_inuse_max_bytes":1048576},
    {"test":"Load_Multipart","throughput_mbps":80,"latency_ns":{"p50":5000,"p95":8000,"p99":12000},"errors":0,"retries_total":0,"heap_inuse_max_bytes":2097152}
  ]
}
EOF

cat >"$tmp/p99_spike.json" <<EOF
{
  "schema_version": "1",
  "provider": "garage",
  "runs": [
    {"test":"Load_RangeRead","throughput_mbps":100,"latency_ns":{"p50":1000,"p95":2000,"p99":4000},"errors":0,"retries_total":0,"heap_inuse_max_bytes":1048576}
  ]
}
EOF

cat >"$tmp/errors.json" <<EOF
{
  "schema_version": "1",
  "provider": "minio",
  "runs": [
    {"test":"Load_RangeRead","throughput_mbps":100,"latency_ns":{"p50":1000,"p95":2000,"p99":3000},"errors":3,"retries_total":0,"heap_inuse_max_bytes":1048576}
  ]
}
EOF

cat >"$tmp/placeholder.json" <<EOF
{
  "schema_version": "1",
  "provider": "minio",
  "runs": []
}
EOF

# --- tests ------------------------------------------------------------------
assert_exit 0 'same as baseline → exit 0' "$script" macro "$tmp/base.json" "$tmp/same.json"
assert_exit 1 'throughput -20% minio → exit 1' "$script" macro "$tmp/base.json" "$tmp/throughput_drop.json"
assert_exit 1 'latency p99 +33% garage → exit 1' "$script" macro "$tmp/base.json" "$tmp/p99_spike.json"
assert_exit 1 'errors 3 where baseline 0 → exit 1' "$script" macro "$tmp/base.json" "$tmp/errors.json"
assert_exit 0 'placeholder baseline → exit 0 (skip)' "$script" macro "$tmp/placeholder.json" "$tmp/same.json"
assert_exit 1 'placeholder new → exit 1' "$script" macro "$tmp/base.json" "$tmp/placeholder.json"

echo
printf 'bench-compare_test: %d passed, %d failed\n' "$pass" "$fail"
if [[ $fail -gt 0 ]]; then
  exit 1
fi
