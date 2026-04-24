#!/usr/bin/env bash
# coverage-gate.sh — Enforce a minimum statement coverage threshold.
#
# Usage:
#   bash scripts/coverage-gate.sh [THRESHOLD]
#
# Arguments:
#   THRESHOLD  Minimum coverage percentage (integer). Defaults to
#              $COVERAGE_THRESHOLD env var, then 75.
#
# Exit codes:
#   0  Coverage meets or exceeds the threshold.
#   1  Coverage is below the threshold, or the run itself failed.
#
# V0.6-QA-2 §4 Phase A

set -euo pipefail

# ── Threshold ────────────────────────────────────────────────────────────────

THRESHOLD="${1:-${COVERAGE_THRESHOLD:-75}}"

if ! [[ "$THRESHOLD" =~ ^[0-9]+$ ]]; then
  echo "ERROR: THRESHOLD must be a non-negative integer, got: $THRESHOLD" >&2
  exit 1
fi

# ── Build the -coverpkg exclusion list ───────────────────────────────────────
# Packages in coverage-exclude.txt are removed from the measured set.

EXCLUDE_FILE="$(dirname "$0")/coverage-exclude.txt"
EXCLUDE_PKGS=()

if [[ -f "$EXCLUDE_FILE" ]]; then
  while IFS= read -r line; do
    # Skip blank lines and comment lines starting with #
    [[ -z "$line" || "$line" == \#* ]] && continue
    EXCLUDE_PKGS+=("$line")
  done < "$EXCLUDE_FILE"
fi

# ── Discover all packages under ./... ────────────────────────────────────────

ALL_PKGS=$(go list ./... 2>/dev/null)

# Filter out excluded packages (exact or suffix match)
INCLUDED_PKGS=()
MODULE=$(go list -m 2>/dev/null)

for pkg in $ALL_PKGS; do
  excluded=false
  for excl in "${EXCLUDE_PKGS[@]+"${EXCLUDE_PKGS[@]}"}"; do
    # excl may be a relative path like "cmd/server" → convert to full pkg path
    full_excl="${MODULE}/${excl}"
    # Also handle file-level excludes (like test/provider/external.go) by
    # matching the package prefix
    excl_pkg="${MODULE}/$(dirname "$excl")"
    if [[ "$pkg" == "$full_excl" || "$pkg" == "${full_excl%.go}" ]]; then
      excluded=true
      break
    fi
    # If the exclusion ends in .go (file-level), match the containing package
    if [[ "$excl" == *.go && "$pkg" == "$excl_pkg" ]]; then
      excluded=true
      break
    fi
  done
  if ! $excluded; then
    INCLUDED_PKGS+=("$pkg")
  fi
done

if [[ ${#INCLUDED_PKGS[@]} -eq 0 ]]; then
  echo "ERROR: No packages to test after applying exclusions." >&2
  exit 1
fi

# Comma-separated list for -coverpkg
COVERPKG=$(IFS=','; echo "${INCLUDED_PKGS[*]}")

# ── Run tests with coverage ───────────────────────────────────────────────────

PROFILE="${COVERAGE_PROFILE:-coverage.out}"
FIPS_PROFILE="${FIPS_COVERAGE_PROFILE:-coverage-fips.out}"
TAGS="${COVERAGE_TAGS:-}"

echo "=== Coverage Gate ==="
echo "Threshold: ${THRESHOLD}%"
echo "Tags: ${TAGS:-<none>}"
echo "Excluded packages:"
for excl in "${EXCLUDE_PKGS[@]+"${EXCLUDE_PKGS[@]}"}"; do
  echo "  - $excl"
done
echo ""

TAG_ARGS=()
if [[ -n "$TAGS" ]]; then
  TAG_ARGS=("-tags" "$TAGS")
fi

echo "Running: go test -count=1 -short -covermode=atomic -coverprofile=${PROFILE} -coverpkg=${COVERPKG} ${TAG_ARGS[*]+"${TAG_ARGS[@]}"} ./..."
go test -count=1 -short \
  -covermode=atomic \
  -coverprofile="${PROFILE}" \
  -coverpkg="${COVERPKG}" \
  "${TAG_ARGS[@]+"${TAG_ARGS[@]}"}" \
  ./... 2>&1

# ── Parse total coverage ──────────────────────────────────────────────────────

if [[ ! -f "$PROFILE" ]]; then
  echo "ERROR: Coverage profile not found: $PROFILE" >&2
  exit 1
fi

TOTAL_LINE=$(go tool cover -func="${PROFILE}" | grep "^total:" || true)
if [[ -z "$TOTAL_LINE" ]]; then
  echo "ERROR: Could not find total coverage in profile. Profile may be malformed." >&2
  exit 1
fi

# Extract the numeric percentage (e.g. "80.1" from "total: (statements)   80.1%")
TOTAL_PCT=$(echo "$TOTAL_LINE" | awk '{print $3}' | tr -d '%')

if [[ -z "$TOTAL_PCT" ]]; then
  echo "ERROR: Could not parse coverage percentage from: $TOTAL_LINE" >&2
  exit 1
fi

# ── Per-package table ─────────────────────────────────────────────────────────

echo ""
echo "=== Per-package coverage ==="
go tool cover -func="${PROFILE}" | grep -v "^total:" | awk '
  /\.(go):/{
    split($1, parts, ":")
    file = parts[1]
    n = split(file, segs, "/")
    # Use last two path segments as the package+file identifier
    pkg = (n >= 2) ? segs[n-1] "/" segs[n] : segs[n]
    func_ = $2
    cov = $3
  }
' 2>/dev/null || true

# Print the per-function output in a compact way
go tool cover -func="${PROFILE}" | grep -v "^total:" | \
  awk 'NR%1==0{print}' | column -t 2>/dev/null || \
  go tool cover -func="${PROFILE}" | grep -v "^total:"

echo ""
echo "=== Total ==="
echo "$TOTAL_LINE"
echo ""

# ── GitHub Actions step summary ───────────────────────────────────────────────

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## Coverage Gate"
    echo ""
    echo "| Metric | Value |"
    echo "|--------|-------|"
    echo "| Total statement coverage | ${TOTAL_PCT}% |"
    echo "| Threshold | ${THRESHOLD}% |"
    echo "| Tags | ${TAGS:-default} |"
    echo ""
    echo "### Per-package coverage"
    echo ""
    echo '```'
    go tool cover -func="${PROFILE}"
    echo '```'
  } >> "$GITHUB_STEP_SUMMARY"
fi

# ── Generate HTML report (optional) ──────────────────────────────────────────

if [[ -n "${COVERAGE_HTML:-}" ]]; then
  go tool cover -html="${PROFILE}" -o "${COVERAGE_HTML}"
  echo "HTML report written to: ${COVERAGE_HTML}"
fi

# ── Threshold comparison ──────────────────────────────────────────────────────

# Strip decimal for integer comparison: floor(TOTAL_PCT)
TOTAL_INT=$(echo "$TOTAL_PCT" | awk -F. '{print $1}')

if (( TOTAL_INT >= THRESHOLD )); then
  echo "PASS: ${TOTAL_PCT}% >= ${THRESHOLD}% threshold"
  exit 0
else
  echo "FAIL: ${TOTAL_PCT}% < ${THRESHOLD}% threshold" >&2
  echo "To see uncovered lines: go tool cover -html=${PROFILE}" >&2
  exit 1
fi
