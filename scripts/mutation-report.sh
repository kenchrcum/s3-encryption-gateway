#!/usr/bin/env bash
# mutation-report.sh — Run Gremlins mutation testing on the in-scope packages.
#
# Usage:
#   bash scripts/mutation-report.sh [PKG ...]
#
# Arguments:
#   PKG ...  One or more package paths to test. Defaults to the four in-scope
#            packages: internal/config, internal/api, internal/s3,
#            internal/middleware.
#
# Exit codes:
#   0  Kill-rate meets or exceeds MUTATION_THRESHOLD for all packages.
#   1  Kill-rate is below threshold for at least one package, or run failed.
#
# Prerequisites:
#   gremlins must be installed:
#     go install github.com/go-gremlins/gremlins/cmd/gremlins@latest
#
# V0.6-QA-2 §4 Phase C

set -euo pipefail

MUTATION_THRESHOLD="${MUTATION_THRESHOLD:-70}"
REPORT_DIR="${MUTATION_REPORT_DIR:-docs/mutation}"

# Default packages if none provided
if [[ $# -eq 0 ]]; then
  PACKAGES=(
    "./internal/config"
    "./internal/api"
    "./internal/s3"
    "./internal/middleware"
  )
else
  PACKAGES=("$@")
fi

# Verify gremlins is available
if ! command -v gremlins >/dev/null 2>&1; then
  # Try GOPATH/bin
  GOPATH_BIN="${GOPATH:-$HOME/go}/bin"
  if [[ -x "${GOPATH_BIN}/gremlins" ]]; then
    export PATH="${GOPATH_BIN}:${PATH}"
  else
    echo "ERROR: gremlins not found. Install with:" >&2
    echo "  go install github.com/go-gremlins/gremlins/cmd/gremlins@latest" >&2
    exit 1
  fi
fi

mkdir -p "${REPORT_DIR}"

overall_pass=true

echo "=== Mutation Testing Report ==="
echo "Threshold: ${MUTATION_THRESHOLD}% kill-rate"
echo "Packages: ${PACKAGES[*]}"
echo ""

for pkg in "${PACKAGES[@]}"; do
  # Derive a short name for the report file (e.g. internal/config → config)
  short_name=$(basename "$pkg")
  report_file="${REPORT_DIR}/${short_name}.json"

  echo "--- Package: ${pkg} ---"

  # Run gremlins; capture exit code without set -e killing us
  set +e
  gremlins unleash \
    --threshold-efficacy="${MUTATION_THRESHOLD}" \
    --only-covered \
    --output=json \
    --json-output="${report_file}" \
    "${pkg}" 2>&1
  exit_code=$?
  set -e

  if [[ $exit_code -ne 0 ]]; then
    echo "FAIL: Package ${pkg} did not meet kill-rate threshold ${MUTATION_THRESHOLD}%" >&2
    overall_pass=false
  else
    echo "PASS: Package ${pkg}"
  fi

  # Print summary table if report exists
  if [[ -f "${report_file}" ]]; then
    echo "  Report: ${report_file}"
    # Parse JSON for basic stats if jq is available
    if command -v jq >/dev/null 2>&1; then
      jq -r '
        .mutants // [] |
        {
          total: length,
          killed: [.[] | select(.status == "KILLED")] | length,
          lived: [.[] | select(.status == "LIVED")] | length,
          timeout: [.[] | select(.status == "TIMEOUT")] | length,
          not_covered: [.[] | select(.status == "NOT_COVERED")] | length
        } |
        "  Killed: \(.killed)/\(.total) | Lived: \(.lived) | Timeout: \(.timeout) | Not covered: \(.not_covered)"
      ' "${report_file}" 2>/dev/null || true
    fi
  fi
  echo ""
done

# GitHub Actions step summary
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## Mutation Testing Report"
    echo ""
    echo "| Package | Kill-rate threshold | Status |"
    echo "|---------|--------------------:|--------|"
    for pkg in "${PACKAGES[@]}"; do
      short_name=$(basename "$pkg")
      report_file="${REPORT_DIR}/${short_name}.json"
      status="unknown"
      if [[ -f "${report_file}" ]] && command -v jq >/dev/null 2>&1; then
        rate=$(jq -r '
          .mutants // [] |
          if length == 0 then "N/A"
          else
            (([.[] | select(.status == "KILLED")] | length) / length * 100) | round | tostring + "%"
          end
        ' "${report_file}" 2>/dev/null || echo "N/A")
        status="${rate}"
      fi
      echo "| ${pkg} | ${MUTATION_THRESHOLD}% | ${status} |"
    done
  } >> "$GITHUB_STEP_SUMMARY"
fi

if $overall_pass; then
  echo "=== ALL PASS: kill-rate ≥ ${MUTATION_THRESHOLD}% for all packages ==="
  exit 0
else
  echo "=== FAIL: one or more packages below ${MUTATION_THRESHOLD}% kill-rate ===" >&2
  exit 1
fi
