#!/usr/bin/env bash
# schema-drift.sh — detect keys in values.yaml that are missing from values.schema.json
#
# This script extracts the set of dot-path leaf keys from values.yaml using
# the helm-values-schema-json plugin and compares the key names against the
# hand-written values.schema.json on a KEY PRESENCE basis only (not content).
#
# A CI failure here means a new value was added to values.yaml but not
# documented/validated in the schema. The fix is to add the new key to
# values.schema.json with at minimum a type and description.
#
# Usage:
#   bash helm/s3-encryption-gateway/scripts/schema-drift.sh
#
# Requirements:
#   helm plugin install https://github.com/losisin/helm-values-schema-json
#   (installs as `helm schema` sub-command)
#   yq v4 (for YAML parsing)
#
# Exit 0: no drift detected (schema covers all keys in values.yaml).
# Exit 1: drift detected (schema is missing one or more keys).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="$(dirname "$SCRIPT_DIR")"

SCHEMA_FILE="$CHART_DIR/values.schema.json"
VALUES_FILE="$CHART_DIR/values.yaml"
TMPDIR_WORK="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_WORK"' EXIT

echo "Schema drift check"
echo "  Schema:  $SCHEMA_FILE"
echo "  Values:  $VALUES_FILE"
echo ""

# ── Step 1: Generate a flat list of JSON-path leaf keys from values.yaml ──
# We use yq to flatten the YAML into dot-separated paths, then strip the
# leading '.' from each path.
if ! command -v yq &>/dev/null; then
  echo "ERROR: yq is required for the drift check. Install with: brew install yq"
  echo "       or: pip install yq"
  exit 1
fi

VALUES_KEYS="$TMPDIR_WORK/values_keys.txt"
# Emit dot-joined paths to every scalar leaf in values.yaml. We use `-r` (raw
# output) so each line is an unquoted, `.`-separated path such as
# `image.repository` or `config.backend.accessKey.value`. Path components that
# are integers (array indices) are stripped with `tostring` only where needed;
# we exclude them from comparison in the awk filter below since array indices
# are not schema property names.
yq -r '[path(.. | select(type != "null" and (type == "string" or type == "number" or type == "boolean")))] | .[] | join(".")' "$VALUES_FILE" \
  | sort -u > "$VALUES_KEYS" || true

# Known free-form sub-trees where the schema declares `additionalProperties:
# true` (e.g. podSecurityContext, securityContext, resources.limits, etc.).
# Leaf keys beneath these paths are Kubernetes-native fields that do not need
# explicit schema enumeration — Kubernetes API validation applies downstream.
# Excluding them from drift keeps the check focused on the gateway's own
# configuration surface where typos matter.
#
# The regex is anchored at the start of a path. Paths whose prefix matches
# ANY of these are skipped from drift comparison.
FREE_FORM_PREFIXES=(
  "podSecurityContext\\."
  "securityContext\\."
  "resources\\.limits\\."
  "resources\\.requests\\."
  "autoscaling\\.behavior\\."
  "ingress\\.hosts\\."
  "ingress\\.tls\\."
  "certManager\\.issuer\\."
  "certManager\\.certificate\\."
  "extraEnv\\."
  "extraVolumes\\."
  "extraVolumeMounts\\."
  "initContainers\\."
  "sidecars\\."
  "tolerations\\."
  "affinity\\."
  "topologySpreadConstraints\\."
  "valkey\\.auth\\."
  "livenessProbe\\."
  "readinessProbe\\."
  "config\\.admin\\."
)
FREE_FORM_RE="^($(IFS=\| ; echo "${FREE_FORM_PREFIXES[*]}"))"

VALUES_KEYS_FILTERED="$TMPDIR_WORK/values_keys_filtered.txt"
grep -Ev "$FREE_FORM_RE" "$VALUES_KEYS" > "$VALUES_KEYS_FILTERED" || true
mv "$VALUES_KEYS_FILTERED" "$VALUES_KEYS"

# ── Step 2: Extract all property key names from values.schema.json ──
# jq is preferred for precise key extraction (all `properties` object keys
# recursively, regardless of nesting depth or `$defs` reuse). This correctly
# picks up keys defined inside $defs/configValue, $defs/probe, etc.
SCHEMA_KEYS="$TMPDIR_WORK/schema_keys.txt"
if command -v jq &>/dev/null; then
  jq -r '[.. | objects | .properties? // {} | keys[]] | unique[]' \
    "$SCHEMA_FILE" | sort -u > "$SCHEMA_KEYS" 2>/dev/null || true
else
  # Fallback: grep for "key": { patterns in the schema
  grep -oE '"[a-zA-Z_][a-zA-Z0-9_]*"[[:space:]]*:[[:space:]]*\{' "$SCHEMA_FILE" \
    | grep -oE '"[a-zA-Z_][a-zA-Z0-9_]*"' \
    | tr -d '"' | sort -u > "$SCHEMA_KEYS" || true
fi

# ── Step 3: Compare — find values.yaml leaf-path segments not in schema ──
# We compare the LAST path segment (leaf key name) since the schema uses
# $defs for reuse and JSON paths don't map directly to schema property paths.
#
# The filter:
#   - drops empty lines
#   - drops purely-numeric segments (array indices like `0`, `1`)
#   - lower-cases nothing (schema keys are exact-case)
VALUES_LEAF_KEYS="$TMPDIR_WORK/values_leaf_keys.txt"
awk -F'.' 'NF>0 { leaf=$NF; if (leaf ~ /^[0-9]+$/) next; print leaf }' "$VALUES_KEYS" \
  | sort -u > "$VALUES_LEAF_KEYS" || true

MISSING="$TMPDIR_WORK/missing_keys.txt"
comm -23 "$VALUES_LEAF_KEYS" "$SCHEMA_KEYS" > "$MISSING" || true

if [[ -s "$MISSING" ]]; then
  echo "DRIFT DETECTED — the following leaf key name(s) from values.yaml are"
  echo "not found in values.schema.json. Add them with at minimum a type and"
  echo "description to pass this check:"
  echo ""
  while IFS= read -r key; do
    # Show which values.yaml paths contain this key
    echo "  Missing key: $key"
    grep -E "(^|\\.)${key}$" "$VALUES_KEYS" | head -3 | sed 's/^/    path: /'
  done < "$MISSING"
  echo ""
  exit 1
else
  echo "No schema drift detected. All keys in values.yaml are covered by the schema."
  exit 0
fi
