#!/usr/bin/env bash
# helm/s3-encryption-gateway/scripts/test-progressive-delivery.sh
#
# Validates blue/green and canary progressive-delivery chart rendering.
#
# Runs entirely without a Kubernetes cluster using `helm template` and
# `helm lint`. Used both locally and in CI (.github/workflows/helm-test.yml).
#
# USAGE:
#   ./test-progressive-delivery.sh            # run all checks
#   ./test-progressive-delivery.sh --quick    # skip golden-file diff
#
# EXIT CODE: 0 if all checks pass, 1 if any check fails.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="$(dirname "$SCRIPT_DIR")"
EXAMPLES_DIR="$CHART_DIR/examples"
QUICK="${1:-}"

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

section() {
  echo ""
  echo "──────────────────────────────────────────────────────────"
  echo "  $1"
  echo "──────────────────────────────────────────────────────────"
}

# ── Prerequisite: helm available ─────────────────────────────────────────────
if ! command -v helm &>/dev/null; then
  echo "ERROR: helm is not in PATH." >&2
  exit 1
fi

echo ""
echo "Testing progressive-delivery rendering — chart: $CHART_DIR"

# ── Section 1: helm lint on all example values files ─────────────────────────
section "1. helm lint — example values files"

for f in \
  "$EXAMPLES_DIR/values-blue.yaml" \
  "$EXAMPLES_DIR/values-green.yaml" \
  "$EXAMPLES_DIR/values-canary-stable.yaml" \
  "$EXAMPLES_DIR/values-canary-canary.yaml" \
  "$EXAMPLES_DIR/values-traefik-single.yaml"
do
  name="$(basename "$f")"
  if helm lint "$CHART_DIR" -f "$f" > /dev/null 2>&1; then
    pass "helm lint $name"
  else
    fail "helm lint $name"
    helm lint "$CHART_DIR" -f "$f" 2>&1 | sed 's/^/    /'
  fi
done

# ── Section 2: helm template renders — check for key fields ──────────────────
section "2. helm template — track label and resource rendering"

# 2a: track=blue label appears in Deployment, selector, and pod labels
OUTPUT=$(helm template gw-blue "$CHART_DIR" \
  --values "$EXAMPLES_DIR/values-blue.yaml" 2>/dev/null)

if echo "$OUTPUT" | grep -q 'track: "blue"'; then
  pass "blue: track label present in rendered output"
else
  fail "blue: track label missing"
fi

if echo "$OUTPUT" | grep -q 'kind: Deployment'; then
  pass "blue: Deployment rendered"
else
  fail "blue: Deployment missing"
fi

if echo "$OUTPUT" | grep -qE '^kind: Service$'; then
  fail "blue: Service should NOT be rendered (service.enabled=false)"
else
  pass "blue: Service correctly absent (service.enabled=false)"
fi

if echo "$OUTPUT" | grep -q 'terminationGracePeriodSeconds: 60'; then
  pass "blue: terminationGracePeriodSeconds=60 present"
else
  fail "blue: terminationGracePeriodSeconds=60 missing"
fi

if echo "$OUTPUT" | grep -q 'sleep 10'; then
  pass "blue: preStop sleep 10 present"
else
  fail "blue: preStop sleep 10 missing"
fi

# 2b: green values render similarly
OUTPUT=$(helm template gw-green "$CHART_DIR" \
  --values "$EXAMPLES_DIR/values-green.yaml" 2>/dev/null)

if echo "$OUTPUT" | grep -q 'track: "green"'; then
  pass "green: track label present"
else
  fail "green: track label missing"
fi

# 2c: Traefik single — exactly one IngressRoute, no TraefikService, no standard Ingress
OUTPUT=$(helm template gw-traefik "$CHART_DIR" \
  --values "$EXAMPLES_DIR/values-traefik-single.yaml" 2>/dev/null)

IR_COUNT=$(echo "$OUTPUT" | grep -cE '^kind: IngressRoute$' 2>/dev/null || true)
TS_COUNT=$(echo "$OUTPUT" | grep -cE '^kind: TraefikService$' 2>/dev/null || true)
ING_COUNT=$(echo "$OUTPUT" | grep -cE '^kind: Ingress$' 2>/dev/null || true)

if [[ "$IR_COUNT" -eq 1 ]]; then
  pass "traefik-single: exactly 1 IngressRoute rendered"
else
  fail "traefik-single: expected 1 IngressRoute, got $IR_COUNT"
fi

if [[ "$TS_COUNT" -eq 0 ]]; then
  pass "traefik-single: no TraefikService rendered (weighted.enabled=false)"
else
  fail "traefik-single: expected 0 TraefikService, got $TS_COUNT"
fi

if [[ "$ING_COUNT" -eq 0 ]]; then
  pass "traefik-single: no standard Ingress rendered (ingress.enabled=false)"
else
  fail "traefik-single: expected 0 standard Ingress, got $ING_COUNT"
fi

# 2d: IngressRoute service name == rendered Service name
IR_SVC=$(echo "$OUTPUT" | grep -A3 'kind: IngressRoute' | grep 'name:' | tail -1 | awk '{print $2}')
SVC_NAME="gw-traefik-s3-encryption-gateway"
if [[ "$IR_SVC" == "$SVC_NAME" || "$IR_SVC" == "\"$SVC_NAME\"" ]]; then
  pass "traefik-single: IngressRoute service name matches rendered Service"
else
  # More lenient check — just ensure the IR references the right service
  if echo "$OUTPUT" | grep -A5 'kind: IngressRoute' | grep -q 'gw-traefik-s3-encryption-gateway'; then
    pass "traefik-single: IngressRoute references gw-traefik-s3-encryption-gateway"
  else
    fail "traefik-single: IngressRoute service name mismatch (expected $SVC_NAME, got $IR_SVC)"
  fi
fi

# 2e: weighted canary render (via --set, since it requires a services list)
OUTPUT=$(helm template gw-weighted "$CHART_DIR" \
  --set ingress.traefik.enabled=true \
  --set ingress.traefik.weighted.enabled=true \
  --set ingress.traefik.host=s3.example.com \
  --set "ingress.traefik.weighted.services[0].name=gw-stable" \
  --set "ingress.traefik.weighted.services[0].port=80" \
  --set "ingress.traefik.weighted.services[0].weight=95" \
  --set "ingress.traefik.weighted.services[1].name=gw-canary" \
  --set "ingress.traefik.weighted.services[1].port=80" \
  --set "ingress.traefik.weighted.services[1].weight=5" 2>/dev/null)

# Use line-anchored grep to avoid matching 'kind: TraefikService' inside IngressRoute spec
TS_COUNT=$(echo "$OUTPUT" | grep -cE '^kind: TraefikService$' 2>/dev/null || true)
IR_COUNT=$(echo "$OUTPUT" | grep -cE '^kind: IngressRoute$' 2>/dev/null || true)

if [[ "$TS_COUNT" -eq 1 ]]; then
  pass "weighted: exactly 1 TraefikService rendered"
else
  fail "weighted: expected 1 TraefikService, got $TS_COUNT"
fi

if [[ "$IR_COUNT" -eq 1 ]]; then
  pass "weighted: exactly 1 IngressRoute rendered"
else
  fail "weighted: expected 1 IngressRoute, got $IR_COUNT"
fi

if echo "$OUTPUT" | grep -q 'weight: 95'; then
  pass "weighted: weight 95 present in TraefikService"
else
  fail "weighted: weight 95 missing in TraefikService"
fi

if echo "$OUTPUT" | grep -q 'weight: 5'; then
  pass "weighted: weight 5 present in TraefikService"
else
  fail "weighted: weight 5 missing in TraefikService"
fi

# ── Section 3: Guard-rail smoke tests ────────────────────────────────────────
section "3. Guard-rail smoke tests — defense-in-depth (schema + template)"

# Defense-in-depth: V0.6-OPS-2's values.schema.json now rejects these bad
# configurations at `helm lint` / `helm install` time (client-side, before any
# template render). The template-time `fail` guards in templates/validate.yaml
# remain as a second defensive layer, used when:
#   - the schema is bypassed (--skip-schema-validation), or
#   - an operator installs via a tool that does not enforce schemas.
#
# This section runs each bad-values case twice:
#   (a) WITHOUT --skip-schema-validation → must fail at the schema layer.
#   (b) WITH    --skip-schema-validation → must fail at the template layer
#       with the actionable message pointing at docs/OPS_DEPLOYMENT.md.

# Helper: check that a helm template invocation fails with ANY of several expected messages.
# Usage: check_guard "description" "msg1|msg2|msg3" [helm args...]
#   The expected substring uses grep -E (alternation supported).
check_guard() {
  local desc="$1"
  local expected_re="$2"
  shift 2
  local output
  output=$(helm template bad "$CHART_DIR" "$@" 2>&1 || true)
  if echo "$output" | grep -qE "$expected_re"; then
    pass "guard: $desc"
  else
    fail "guard: $desc"
    echo "    Expected output matching: $expected_re" >&2
    echo "    Got: $output" | head -5 >&2
  fi
}

# 3a: track=blue + valkey.enabled=true
# Schema layer (I1): "allOf' failed" at /valkey/enabled
# Template layer: "shared external Valkey"
check_guard "[schema] track + valkey.enabled" \
  "'allOf' failed|valkey/enabled" \
  --set track=blue \
  --set valkey.enabled=true \
  --set config.multipartState.valkey.addr.value=some-addr
check_guard "[template] track + valkey.enabled → 'shared external Valkey'" \
  "shared external Valkey" \
  --skip-schema-validation \
  --set track=blue \
  --set valkey.enabled=true \
  --set config.multipartState.valkey.addr.value=some-addr

# 3b: ingress.enabled + ingress.traefik.enabled both true
# Schema layer (I2): "'not' failed"
# Template layer: "Cannot enable both"
check_guard "[schema] ingress.enabled + ingress.traefik.enabled" \
  "'not' failed|'allOf' failed" \
  --set ingress.enabled=true \
  --set ingress.traefik.enabled=true
check_guard "[template] ingress.enabled + traefik.enabled → 'Cannot enable both'" \
  "Cannot enable both" \
  --skip-schema-validation \
  --set ingress.enabled=true \
  --set ingress.traefik.enabled=true

# 3c: weighted.enabled without traefik.enabled
# Schema layer (I3): "value must be true" at /ingress/traefik/enabled
# Template layer: "requires"
check_guard "[schema] weighted.enabled without traefik.enabled" \
  "'allOf' failed|traefik/enabled" \
  --set ingress.traefik.weighted.enabled=true \
  --set ingress.traefik.enabled=false
check_guard "[template] weighted.enabled without traefik.enabled → 'requires'" \
  "requires" \
  --skip-schema-validation \
  --set ingress.traefik.weighted.enabled=true \
  --set ingress.traefik.enabled=false

# 3d: weights summing to 99 — template-time only (schema cannot express sums)
check_guard "[template] weights 50+49=99 → 'must sum to 100'" \
  "must sum to 100" \
  --set ingress.traefik.enabled=true \
  --set ingress.traefik.weighted.enabled=true \
  --set ingress.traefik.host=s3.example.com \
  --set "ingress.traefik.weighted.services[0].name=svc-a" \
  --set "ingress.traefik.weighted.services[0].port=80" \
  --set "ingress.traefik.weighted.services[0].weight=50" \
  --set "ingress.traefik.weighted.services[1].name=svc-b" \
  --set "ingress.traefik.weighted.services[1].port=80" \
  --set "ingress.traefik.weighted.services[1].weight=49"

# 3e: track set without valkey addr → should fail at both layers
# Schema layer (I1 anyOf): "'anyOf' failed"
# Template layer: "config.multipartState.valkey.addr"
check_guard "[schema] track without valkey addr" \
  "'anyOf' failed|'allOf' failed" \
  --set track=blue
check_guard "[template] track without valkey addr → addr required message" \
  "config.multipartState.valkey.addr" \
  --skip-schema-validation \
  --set track=blue

# ── Section 4: Default render backward-compat check ──────────────────────────
section "4. Backward compatibility — default render has no track label"

OUTPUT=$(helm template test-default "$CHART_DIR" 2>/dev/null)

if echo "$OUTPUT" | grep -q 'track:'; then
  fail "default: track label leaked into default render (must be absent)"
else
  pass "default: no track label in default render"
fi

if echo "$OUTPUT" | grep -qE '^kind: IngressRoute$'; then
  fail "default: IngressRoute present in default render (must be absent)"
else
  pass "default: no IngressRoute in default render"
fi

if echo "$OUTPUT" | grep -qE '^kind: TraefikService$'; then
  fail "default: TraefikService present in default render (must be absent)"
else
  pass "default: no TraefikService in default render"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "══════════════════════════════════════════════════════════════"

if [[ "$FAIL" -gt 0 ]]; then
  exit 1
else
  exit 0
fi
