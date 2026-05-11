#!/bin/bash
set -euo pipefail

# Test script for Helm chart
# Validates that the chart renders correctly with different configurations

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="$(dirname "$SCRIPT_DIR")"

echo "Testing Helm chart: $CHART_DIR"

# Test 1: Default configuration with backend and auth credentials
echo ""
echo "Test 1: Default configuration with credentials"
helm template test "$CHART_DIR" \
  --set config.backend.accessKey.value=test-access-key \
  --set config.backend.secretKey.value=test-secret-key \
  --set config.auth.credentials[0].accessKey.value=gw-access-key \
  --set config.auth.credentials[0].secretKey.value=gw-secret-key \
  --set config.encryption.password.value=test-password > /dev/null

if helm template test "$CHART_DIR" \
  --set config.backend.accessKey.value=test-access-key \
  --set config.backend.secretKey.value=test-secret-key \
  --set config.auth.credentials[0].accessKey.value=gw-access-key \
  --set config.auth.credentials[0].secretKey.value=gw-secret-key \
  --set config.encryption.password.value=test-password 2>&1 | grep -q "BACKEND_ACCESS_KEY"; then
  echo "✓ BACKEND_ACCESS_KEY is present"
else
  echo "✗ BACKEND_ACCESS_KEY is missing"
  exit 1
fi

if helm template test "$CHART_DIR" \
  --set config.backend.accessKey.value=test-access-key \
  --set config.backend.secretKey.value=test-secret-key \
  --set config.auth.credentials[0].accessKey.value=gw-access-key \
  --set config.auth.credentials[0].secretKey.value=gw-secret-key \
  --set config.encryption.password.value=test-password 2>&1 | grep -q "BACKEND_SECRET_KEY"; then
  echo "✓ BACKEND_SECRET_KEY is present"
else
  echo "✗ BACKEND_SECRET_KEY is missing"
  exit 1
fi

if helm template test "$CHART_DIR" \
  --set config.backend.accessKey.value=test-access-key \
  --set config.backend.secretKey.value=test-secret-key \
  --set config.auth.credentials[0].accessKey.value=gw-access-key \
  --set config.auth.credentials[0].secretKey.value=gw-secret-key \
  --set config.encryption.password.value=test-password 2>&1 | grep -q "GW_CRED_0_ACCESS_KEY"; then
  echo "✓ GW_CRED_0_ACCESS_KEY is present"
else
  echo "✗ GW_CRED_0_ACCESS_KEY is missing"
  exit 1
fi

# Test 2: existingCredentialsSecret rendering
echo ""
echo "Test 2: existingCredentialsSecret"
helm template test "$CHART_DIR" \
  --set config.auth.existingCredentialsSecret.name=gw-creds \
  --set config.auth.existingCredentialsSecret.key=creds.yaml \
  --set config.backend.accessKey.value=test-access-key \
  --set config.backend.secretKey.value=test-secret-key \
  --set config.encryption.password.value=test-password > /dev/null

if helm template test "$CHART_DIR" \
  --set config.auth.existingCredentialsSecret.name=gw-creds \
  --set config.auth.existingCredentialsSecret.key=creds.yaml \
  --set config.backend.accessKey.value=test-access-key \
  --set config.backend.secretKey.value=test-secret-key \
  --set config.encryption.password.value=test-password 2>&1 | grep -q "AUTH_CREDENTIALS_FILE"; then
  echo "✓ AUTH_CREDENTIALS_FILE is present"
else
  echo "✗ AUTH_CREDENTIALS_FILE is missing"
  exit 1
fi

if helm template test "$CHART_DIR" \
  --set config.auth.existingCredentialsSecret.name=gw-creds \
  --set config.auth.existingCredentialsSecret.key=creds.yaml \
  --set config.backend.accessKey.value=test-access-key \
  --set config.backend.secretKey.value=test-secret-key \
  --set config.encryption.password.value=test-password 2>&1 | grep -q "GW_CRED_0_ACCESS_KEY"; then
  echo "✗ GW_CRED_0_ACCESS_KEY should not be present with existingCredentialsSecret"
  exit 1
else
  echo "✓ GW_CRED_0_ACCESS_KEY correctly excluded"
fi

# Test 3: Validate chart linting
echo ""
echo "Test 3: Helm chart linting"
if helm lint "$CHART_DIR" > /dev/null 2>&1; then
  echo "✓ Chart passes linting"
else
  echo "✗ Chart linting failed"
  helm lint "$CHART_DIR"
  exit 1
fi

# Test 4: Schema validation — helm lint with a known-bad values file must fail
echo ""
echo "Test 4: Schema validation rejects invalid values"
BAD_VALUES="$CHART_DIR/tests/schema/bad-replica-string.yaml"
if helm lint "$CHART_DIR" -f "$BAD_VALUES" > /dev/null 2>&1; then
  echo "✗ helm lint should have FAILED for bad values: $BAD_VALUES"
  exit 1
else
  echo "✓ helm lint correctly rejected invalid replicaCount type (string instead of integer)"
fi

BAD_TRACK="$CHART_DIR/tests/schema/bad-track-with-valkey.yaml"
if helm lint "$CHART_DIR" -f "$BAD_TRACK" > /dev/null 2>&1; then
  echo "✗ helm lint should have FAILED for bad values: $BAD_TRACK"
  exit 1
else
  echo "✓ helm lint correctly rejected track+valkey.enabled=true invariant violation (I1)"
fi

echo ""
echo "All tests passed!"
