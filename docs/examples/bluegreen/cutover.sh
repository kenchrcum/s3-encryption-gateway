#!/usr/bin/env bash
# docs/examples/bluegreen/cutover.sh
#
# Blue/green traffic cutover and rollback script.
# Patches the operator-owned shared Service selector to flip traffic between
# the blue and green chart releases.
#
# USAGE:
#   ./cutover.sh green            # flip traffic from blue → green
#   ./cutover.sh blue             # roll back from green → blue
#   NAMESPACE=my-ns ./cutover.sh green
#   SERVICE_NAME=my-svc ./cutover.sh blue
#
# PREREQUISITES:
#   - kubectl is installed and has write access to the Service.
#   - Both Deployments are Ready (the script checks this).
#   - scripts/verify-key-parity.sh returned 0.
#   - Green release was smoke-tested via kubectl port-forward.
#
# AFTER CUTOVER:
#   - Observe error rate and p99 latency for the analysis window (15 min
#     minimum recommended; see docs/OPS_DEPLOYMENT.md §3).
#   - If metrics look good, helm uninstall the old colour after the soak.
#   - If metrics degrade, run: ./cutover.sh blue  (or green)
#
# See docs/OPS_DEPLOYMENT.md §3 for the complete procedure.
set -euo pipefail

NEW_TRACK="${1:-}"
NAMESPACE="${NAMESPACE:-s3-gateway}"
SERVICE_NAME="${SERVICE_NAME:-gateway}"

# ── Validate argument ────────────────────────────────────────────────────────
if [[ -z "$NEW_TRACK" ]]; then
  echo "Usage: $0 {blue|green}" >&2
  echo "  NEW_TRACK: the track label value to flip the Service selector to." >&2
  exit 2
fi

if [[ "$NEW_TRACK" != "blue" && "$NEW_TRACK" != "green" ]]; then
  echo "ERROR: NEW_TRACK must be 'blue' or 'green', got '${NEW_TRACK}'." >&2
  exit 2
fi

ROLLBACK_TRACK="$( [ "$NEW_TRACK" = "green" ] && echo "blue" || echo "green" )"
RELEASE_NAME="gw-${NEW_TRACK}"

echo "=================================================================="
echo " S3 Encryption Gateway — Blue/Green Cutover"
echo " Namespace : ${NAMESPACE}"
echo " Service   : ${SERVICE_NAME}"
echo " Flip to   : ${NEW_TRACK}"
echo " Rollback  : $0 ${ROLLBACK_TRACK}"
echo "=================================================================="

# ── Pre-flight: wait for the target Deployment to be Ready ──────────────────
echo ""
echo "[1/3] Waiting for ${RELEASE_NAME} Deployment to be Available ..."
if ! kubectl -n "${NAMESPACE}" wait \
    --for=condition=available \
    --timeout=120s \
    deployment/"${RELEASE_NAME}" 2>/dev/null; then
  # Try fullname pattern used by Helm: <release>-s3-encryption-gateway
  if ! kubectl -n "${NAMESPACE}" wait \
      --for=condition=available \
      --timeout=120s \
      deployment/"${RELEASE_NAME}-s3-encryption-gateway" 2>/dev/null; then
    echo "ERROR: Could not find a Ready Deployment for release '${RELEASE_NAME}'." >&2
    echo "  Check: kubectl get deployments -n ${NAMESPACE} -l track=${NEW_TRACK}" >&2
    exit 1
  fi
fi
echo "       ${NEW_TRACK} Deployment is Ready."

# ── Flip the selector ────────────────────────────────────────────────────────
echo ""
echo "[2/3] Patching Service '${SERVICE_NAME}' selector to track=${NEW_TRACK} ..."
kubectl -n "${NAMESPACE}" patch service "${SERVICE_NAME}" \
    --type=merge \
    -p "{\"spec\":{\"selector\":{\"app.kubernetes.io/name\":\"s3-encryption-gateway\",\"track\":\"${NEW_TRACK}\"}}}"

# Update the annotation for audit purposes.
kubectl -n "${NAMESPACE}" annotate service "${SERVICE_NAME}" \
    --overwrite \
    "deployment.s3-gateway/active-track=${NEW_TRACK}"

echo "       Service '${SERVICE_NAME}' now selects track=${NEW_TRACK}."
echo ""
echo "[3/3] Cutover complete. kube-proxy propagation takes 5-30 s per node."
echo ""
echo "  Monitor:"
echo "    kubectl -n ${NAMESPACE} get endpointslices -l kubernetes.io/service-name=${SERVICE_NAME}"
echo "    — should show only ${NEW_TRACK} pod IPs within ~30 s."
echo ""
echo "  Prometheus SLI query (per-track):"
echo "    histogram_quantile(0.99, rate(s3_gateway_request_duration_seconds_bucket{track=\"${NEW_TRACK}\"}[5m]))"
echo ""
echo "  Rollback if needed:"
echo "    $0 ${ROLLBACK_TRACK}"
echo ""
echo "  After a clean soak window (≥ 15 min), retire the old colour:"
echo "    helm uninstall gw-${ROLLBACK_TRACK} -n ${NAMESPACE}"
