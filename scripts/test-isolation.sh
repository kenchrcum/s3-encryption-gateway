#!/bin/bash
# scripts/test-isolation.sh
#
# Mechanical enforcement of the Docker-only deployment model for test code.
# Fails if any *.go file under test/ references docker-compose, binary
# exec.Command invocations for backends, or hard-coded well-known ports.
#
# Wired as a required PR check via .github/workflows/conformance.yml so
# the contract cannot regress silently.
#
# Usage:
#   bash scripts/test-isolation.sh        # check and exit non-zero on violation
#   bash scripts/test-isolation.sh --fix  # print violations (no auto-fix)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_DIR="$REPO_ROOT/test"

forbidden_patterns=(
  'docker-compose'
  'exec\.Command.*"garage"'
  'exec\.Command.*"minio"'
  'exec\.LookPath.*"garage"'
  'exec\.LookPath.*"minio"'
  'hasGarageBinary'
  'hasMinIOBinary'
  '"127\.0\.0\.1:9000"'   # hard-coded MinIO port
  '"127\.0\.0\.1:3900"'   # hard-coded Garage S3 port
  '"127\.0\.0\.1:6379"'   # hard-coded Valkey/Redis port
  '"127\.0\.0\.1:5696"'   # hard-coded Cosmian KMIP port
  '"127\.0\.0\.1:9998"'   # hard-coded Cosmian HTTP admin port
)

# Exclusions: these files are explicitly allowed to reference old patterns
# during the migration period (tagged TODO(V0.6-QA-4)).
excluded_files=(
  "test/minio.go"         # legacy shim — to be deleted after harness rewrite
  "test/garage.go"        # legacy shim — to be deleted after harness rewrite
  "test/mpu_fixtures.go"  # legacy shim — to be migrated in Phase 3
)

# The provider/ and harness/ sub-packages are the canonical implementation
# and may contain the patterns as documentation/comments; exclude them.
excluded_dirs=(
  "test/provider"
  "test/harness"
  "test/conformance"
)

fail=0

for pat in "${forbidden_patterns[@]}"; do
  # Build the exclusion args for grep
  exclude_args=()
  for excl in "${excluded_files[@]}"; do
    exclude_args+=(--exclude="$(basename "$excl")")
  done
  for excl_dir in "${excluded_dirs[@]}"; do
    exclude_args+=(--exclude-dir="$(basename "$excl_dir")")
  done

  # Exclude pure comment lines (lines where the first non-whitespace is //)
  matches=$(grep -rEn "$pat" "$TEST_DIR" --include='*.go' \
    "${exclude_args[@]}" 2>/dev/null | grep -v '^\s*//' | grep -v ':[[:space:]]*//' || true)

  if [[ -n "$matches" ]]; then
    echo "VIOLATION: forbidden pattern '$pat' found:" >&2
    echo "$matches" >&2
    echo "  -> Use Testcontainers-Go (test/provider/) instead." >&2
    echo "" >&2
    fail=1
  fi
done

if [[ $fail -eq 0 ]]; then
  echo "test-isolation: OK — no forbidden patterns found in test/"
fi

exit $fail
