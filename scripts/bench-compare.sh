#!/usr/bin/env bash
# V0.6-QA-1 Phase D — bench-compare.
#
# Compares a freshly-run benchmark artefact against a committed baseline and
# exits non-zero if any tracked statistic regresses beyond the threshold in
# plan §6.1. Two modes:
#
#   scripts/bench-compare.sh micro <baseline.txt> <new.txt>
#       Uses benchstat for ns/op, B/op, allocs/op comparisons.
#
#   scripts/bench-compare.sh macro <baseline.json> <new.json>
#       JSON-aware comparator: walks runs[] in both files, computes
#       per-metric deltas, applies §6.1 thresholds, and fails on the first
#       violation. A committed baseline with empty runs[] is treated as
#       "no baseline yet" and exits 0 with a warning.
#
# Thresholds (from plan §6.1):
#   micro ns/op        fail if Δ > +15 % AND p < 0.05
#   micro B/op         fail if Δ > +20 % AND p < 0.05
#   micro allocs/op    fail if Δ >  0    (any new allocation — asymmetric)
#   macro throughput   fail if Δ < -15 %
#   macro p95          fail if Δ > +20 %
#   macro p99          fail if Δ > +25 %
#   macro heap HWM     fail if Δ > +25 %
#   macro errors       fail if any non-zero where baseline = 0
#   macro retries      WARN only (Δ > +50 %) — retry noise is high
#
# Requires:  benchstat (micro mode), jq (macro mode), awk.

set -euo pipefail

# delta_gt BASELINE NEW THRESHOLD_PCT
# Returns 0 iff ((NEW - BASELINE) / BASELINE) * 100 is > THRESHOLD_PCT.
# For negative THRESHOLD_PCT (e.g. -15 for throughput drops), returns 0
# iff the delta is MORE NEGATIVE than the threshold (worse).
delta_gt() {
  local baseline="$1" new_val="$2" thr="$3"
  if [[ "$baseline" == "0" || "$baseline" == "0.0" ]]; then
    awk -v n="$new_val" -v t="$thr" 'BEGIN{
      if (t >= 0) { exit !(n+0 > 0) }
      else        { exit 1 }
    }'
    return $?
  fi
  awk -v b="$baseline" -v n="$new_val" -v t="$thr" 'BEGIN{
    d = ((n + 0 - (b + 0)) / (b + 0)) * 100.0
    if (t >= 0) { exit !(d > t + 0) }
    else        { exit !(d < t + 0) }
  }'
}

compare_micro() {
  local old="$1" new="$2"
  if ! command -v benchstat >/dev/null 2>&1; then
    echo "bench-compare: benchstat not installed (go install golang.org/x/perf/cmd/benchstat@latest)" >&2
    return 4
  fi

  local out
  if ! out="$(benchstat "$old" "$new" 2>&1)"; then
    echo "$out" >&2
    echo "bench-compare(micro): benchstat failed" >&2
    return 5
  fi

  echo "$out"
  echo

  local bad=0
  local unit=""
  while IFS= read -r line; do
    if [[ "$line" =~ (time/op|ns/op) ]]; then
      unit="ns"; continue
    fi
    if [[ "$line" =~ B/op ]]; then
      unit="B"; continue
    fi
    if [[ "$line" =~ allocs/op ]]; then
      unit="allocs"; continue
    fi

    if [[ "$line" =~ ([+-][0-9]+\.[0-9]+)%[[:space:]]+\(p=([0-9.]+) ]]; then
      local delta="${BASH_REMATCH[1]}"
      local pval="${BASH_REMATCH[2]}"
      local bench_name
      bench_name="$(awk '{print $1}' <<<"$line")"

      local thr
      case "$unit" in
        ns)     thr="15" ;;
        B)      thr="20" ;;
        allocs) thr="0"  ;;
        *)      continue ;;
      esac

      if [[ "$unit" == "allocs" ]]; then
        if awk -v d="$delta" 'BEGIN{exit !(d+0 > 0)}'; then
          printf 'REGRESSION %s/allocs: %s%% (p=%s)\n' "$bench_name" "$delta" "$pval" >&2
          bad=$((bad + 1))
        fi
        continue
      fi

      if awk -v d="$delta" -v t="$thr" 'BEGIN{exit !(d+0 > t+0)}' \
         && awk -v p="$pval" 'BEGIN{exit !(p+0 < 0.05)}'; then
        printf 'REGRESSION %s/%s: %s%% (p=%s; threshold +%s%%)\n' "$bench_name" "$unit" "$delta" "$pval" "$thr" >&2
        bad=$((bad + 1))
      fi
    fi
  done <<<"$out"

  if [[ $bad -gt 0 ]]; then
    echo "bench-compare(micro): $bad regression(s) detected" >&2
    return 1
  fi
  echo "bench-compare(micro): no regressions detected"
  return 0
}

compare_macro() {
  local old="$1" new="$2"
  if ! command -v jq >/dev/null 2>&1; then
    echo "bench-compare: jq is required for macro mode" >&2
    return 4
  fi

  local old_runs_len
  old_runs_len="$(jq '.runs | length' "$old")"
  if [[ "$old_runs_len" == "0" ]]; then
    echo "bench-compare(macro): baseline $old has empty runs[]; treating as placeholder — exiting 0." >&2
    return 0
  fi

  local new_runs_len
  new_runs_len="$(jq '.runs | length' "$new")"
  if [[ "$new_runs_len" == "0" ]]; then
    echo "bench-compare(macro): new-run $new has empty runs[]; nothing to compare — failing." >&2
    return 1
  fi

  local bad=0
  local tests
  tests="$(jq -r '.runs[].test' "$new" | sort -u)"
  while IFS= read -r testname; do
    [[ -z "$testname" ]] && continue

    local b_throughput n_throughput
    b_throughput="$(jq --arg t "$testname" '[.runs[] | select(.test==$t)] | first | .throughput_mbps // 0' "$old")"
    n_throughput="$(jq --arg t "$testname" '[.runs[] | select(.test==$t)] | first | .throughput_mbps // 0' "$new")"
    if [[ "$b_throughput" == "null" || -z "$b_throughput" ]]; then
      echo "bench-compare(macro): no baseline row for $testname (treated as pass)" >&2
      continue
    fi

    local b_p95 n_p95 b_p99 n_p99 b_heap n_heap b_errors n_errors b_retries n_retries
    b_p95="$(jq --arg t "$testname" '[.runs[] | select(.test==$t)] | first | .latency_ns.p95 // 0' "$old")"
    n_p95="$(jq --arg t "$testname" '[.runs[] | select(.test==$t)] | first | .latency_ns.p95 // 0' "$new")"
    b_p99="$(jq --arg t "$testname" '[.runs[] | select(.test==$t)] | first | .latency_ns.p99 // 0' "$old")"
    n_p99="$(jq --arg t "$testname" '[.runs[] | select(.test==$t)] | first | .latency_ns.p99 // 0' "$new")"
    b_heap="$(jq --arg t "$testname" '[.runs[] | select(.test==$t)] | first | .heap_inuse_max_bytes // 0' "$old")"
    n_heap="$(jq --arg t "$testname" '[.runs[] | select(.test==$t)] | first | .heap_inuse_max_bytes // 0' "$new")"
    b_errors="$(jq --arg t "$testname" '[.runs[] | select(.test==$t)] | first | .errors // 0' "$old")"
    n_errors="$(jq --arg t "$testname" '[.runs[] | select(.test==$t)] | first | .errors // 0' "$new")"
    b_retries="$(jq --arg t "$testname" '[.runs[] | select(.test==$t)] | first | .retries_total // 0' "$old")"
    n_retries="$(jq --arg t "$testname" '[.runs[] | select(.test==$t)] | first | .retries_total // 0' "$new")"

    if delta_gt "$b_throughput" "$n_throughput" -15; then
      printf 'REGRESSION %s throughput_mbps: baseline=%s new=%s (> -15%% drop)\n' \
        "$testname" "$b_throughput" "$n_throughput" >&2
      bad=$((bad + 1))
    fi
    if delta_gt "$b_p95" "$n_p95" 20; then
      printf 'REGRESSION %s latency_ns.p95: baseline=%s new=%s (> +20%% growth)\n' \
        "$testname" "$b_p95" "$n_p95" >&2
      bad=$((bad + 1))
    fi
    if delta_gt "$b_p99" "$n_p99" 25; then
      printf 'REGRESSION %s latency_ns.p99: baseline=%s new=%s (> +25%% growth)\n' \
        "$testname" "$b_p99" "$n_p99" >&2
      bad=$((bad + 1))
    fi
    if delta_gt "$b_heap" "$n_heap" 25; then
      printf 'REGRESSION %s heap_inuse_max_bytes: baseline=%s new=%s (> +25%% growth)\n' \
        "$testname" "$b_heap" "$n_heap" >&2
      bad=$((bad + 1))
    fi
    if [[ "$b_errors" == "0" ]] && awk -v e="$n_errors" 'BEGIN{exit !(e+0 > 0)}'; then
      printf 'REGRESSION %s errors: baseline=0 new=%s\n' "$testname" "$n_errors" >&2
      bad=$((bad + 1))
    fi
    if [[ "$b_retries" != "0" ]] && delta_gt "$b_retries" "$n_retries" 50; then
      printf 'WARN %s retries_total: baseline=%s new=%s (> +50%% growth — informational)\n' \
        "$testname" "$b_retries" "$n_retries" >&2
    fi
  done <<<"$tests"

  if [[ $bad -gt 0 ]]; then
    echo "bench-compare(macro): $bad regression(s) detected" >&2
    return 1
  fi
  echo "bench-compare(macro): no regressions detected"
  return 0
}

usage() {
  cat >&2 <<EOF
usage:
  $0 micro <baseline.txt> <new.txt>
  $0 macro <baseline.json> <new.json>
EOF
  exit 2
}

mode="${1:-}"
baseline="${2:-}"
new="${3:-}"
if [[ -z "$mode" || -z "$baseline" || -z "$new" ]]; then
  usage
fi
if [[ ! -f "$baseline" ]]; then
  echo "bench-compare: baseline not found: $baseline" >&2
  exit 3
fi
if [[ ! -f "$new" ]]; then
  echo "bench-compare: new-run not found: $new" >&2
  exit 3
fi

case "$mode" in
  micro) compare_micro "$baseline" "$new" ;;
  macro) compare_macro "$baseline" "$new" ;;
  *) usage ;;
esac
