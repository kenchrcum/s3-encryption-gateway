#!/usr/bin/env bash
# V0.6-QA-1 Phase B (§5.4) — bench-lint.
#
# Enforces two invariants for every `func Benchmark...(b *testing.B)` at the
# top level of a *_test.go file:
#
#   1. The body (including anything it *directly* calls if the delegated
#      helper is in the same file) must reach a call to `b.ReportAllocs()`
#      so allocs/op is visible to the nightly regression gate (which fails
#      on any new allocation — see §6.1).
#   2. Likewise for `b.SetBytes(` — OR the benchmark carries a documented
#      exemption comment `// b.SetBytes omitted because ...`.
#
# This lint is intentionally conservative: a benchmark that delegates to a
# private helper in another file is analysed by falling back to file-scope
# (we check the full file for the required call). That is the pragmatic
# approximation §5.4 calls a "grep-level check" — it catches the common
# forget-to-add case without trying to parse Go.
#
# Usage:
#   bash scripts/bench-lint.sh
#
# Exit codes:
#   0 — all benchmarks OK
#   1 — one or more benchmarks are missing ReportAllocs() and/or SetBytes(.

set -euo pipefail

cd "$(dirname "$0")/.."

mapfile -t files < <(
  grep -rl --include='*.go' -E '^func Benchmark[A-Z][A-Za-z0-9_]*\(b \*testing\.B\)' .
)

if [[ ${#files[@]} -eq 0 ]]; then
  echo "bench-lint: no benchmark files found (unexpected)."
  exit 0
fi

bad=0
for f in "${files[@]}"; do
  # File-scope check: whether ReportAllocs/SetBytes appear anywhere in the
  # file. If they do, every top-level benchmark in the file is considered to
  # reach them (via a shared helper or inline). If not, every benchmark is a
  # failure.
  file_has_reportallocs=0
  file_has_setbytes=0
  file_has_setbytes_exemption=0
  grep -Fq 'b.ReportAllocs()' "$f" && file_has_reportallocs=1 || true
  grep -Fq 'b.SetBytes(' "$f" && file_has_setbytes=1 || true
  grep -Eq 'b\.SetBytes omitted because' "$f" && file_has_setbytes_exemption=1 || true

  # List the benchmarks defined in this file for the diagnostic.
  mapfile -t bench_names < <(
    grep -E '^func Benchmark[A-Z][A-Za-z0-9_]*\(b \*testing\.B\)' "$f" \
      | sed -E 's/^func (Benchmark[A-Z][A-Za-z0-9_]*)\(.*/\1/'
  )

  for name in "${bench_names[@]}"; do
    if [[ $file_has_reportallocs -eq 0 ]]; then
      printf '  %s: %s — missing b.ReportAllocs() in file\n' "$f" "$name"
      bad=$((bad + 1))
    fi
    if [[ $file_has_setbytes -eq 0 && $file_has_setbytes_exemption -eq 0 ]]; then
      printf '  %s: %s — missing b.SetBytes( (add a call, or an exemption comment `// b.SetBytes omitted because <reason>`)\n' "$f" "$name"
      bad=$((bad + 1))
    fi
  done
done

if [[ $bad -gt 0 ]]; then
  echo
  echo "bench-lint: $bad benchmark(s) failed the checks above."
  exit 1
fi

echo "bench-lint: all benchmarks passed."
