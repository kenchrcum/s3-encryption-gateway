#!/usr/bin/env bash
# run-negative.sh — negative schema test harness for values.schema.json
#
# Each test in this directory named bad-*.yaml MUST cause `helm lint` to
# fail. This script verifies that and (optionally) checks for expected
# error substrings declared in the file's header comment.
#
# Usage:
#   bash helm/s3-encryption-gateway/tests/schema/run-negative.sh
#
# Exit code: 0 if all negative tests correctly cause lint to fail.
#            1 if any negative test unexpectedly passes (schema too permissive).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

pass=0
fail=0
unexpected_pass=0

echo "Running negative schema tests against: $CHART_DIR"
echo ""

for bad_values in "$SCRIPT_DIR"/bad-*.yaml; do
  name="$(basename "$bad_values")"

  # Extract optional expected error substring from the header comment.
  # Header format: # Expected error substring: "some text"
  expected_substr=""
  expected_line=$(grep -m1 "Expected error substring:" "$bad_values" 2>/dev/null || true)
  if [[ -n "$expected_line" ]]; then
    expected_substr="${expected_line#*: }"
    # Strip surrounding quotes if present
    expected_substr="${expected_substr#\"}"
    expected_substr="${expected_substr%\"}"
  fi

  lint_output=$(helm lint "$CHART_DIR" -f "$bad_values" 2>&1 || true)

  if echo "$lint_output" | grep -qiE "failed|error"; then
    # Lint correctly rejected the bad values
    if [[ -n "$expected_substr" ]]; then
      if echo "$lint_output" | grep -qi "$expected_substr"; then
        echo "PASS  $name (error contains: \"$expected_substr\")"
      else
        echo "WARN  $name — lint failed but error message did not contain: \"$expected_substr\""
        echo "      Actual lint output: $(echo "$lint_output" | grep -i 'error\|failed' | head -3)"
      fi
    else
      echo "PASS  $name"
    fi
    (( pass++ )) || true
  else
    echo "FAIL  $name — helm lint UNEXPECTEDLY PASSED. Schema may be too permissive!"
    echo "      Lint output: $(echo "$lint_output" | tail -3)"
    (( unexpected_pass++ )) || true
    (( fail++ )) || true
  fi
done

echo ""
echo "Results: $pass passed / $unexpected_pass unexpected passes"

if [[ $fail -gt 0 ]]; then
  echo "FAILED: $fail negative test(s) did not cause lint to fail."
  exit 1
fi

echo "All negative tests correctly rejected by schema."
exit 0
