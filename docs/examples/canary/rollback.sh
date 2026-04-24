#!/usr/bin/env bash
# docs/examples/canary/rollback.sh
#
# Emergency canary rollback script.
# Snaps traffic back to 100 % stable, 0 % canary immediately, then removes
# the canary release once in-flight requests have drained.
#
# Use this script when:
#   - Error rate on the canary track exceeds the rollback threshold.
#   - p99 latency on the canary track exceeds the rollback threshold.
#   - A critical bug or panic is observed in canary pod logs.
#
# For a non-emergency gradual rollback, use:
#   docs/examples/canary/promote.sh --rollback
#
# USAGE:
#   ./rollback.sh
#   NAMESPACE=my-ns TRAEFIKSERVICE=my-ts ./rollback.sh
#
# ENVIRONMENT:
#   NAMESPACE        Kubernetes namespace (default: s3-gateway)
#   TRAEFIKSERVICE   Name of the TraefikService (default: gateway-weighted)
#   STABLE_SVC       Stable backend Service name (default: gw-stable-s3-encryption-gateway)
#   CANARY_SVC       Canary backend Service name (default: gw-canary-s3-encryption-gateway)
#   SVC_PORT         Service port (default: 80)
#   DRAIN_SECONDS    Seconds to wait for in-flight requests to drain (default: 60)
#
# See docs/OPS_DEPLOYMENT.md §4 for the complete canary procedure.
set -euo pipefail

NS="${NAMESPACE:-s3-gateway}"
TS="${TRAEFIKSERVICE:-gateway-weighted}"
STABLE_SVC="${STABLE_SVC:-gw-stable-s3-encryption-gateway}"
CANARY_SVC="${CANARY_SVC:-gw-canary-s3-encryption-gateway}"
PORT="${SVC_PORT:-80}"
DRAIN_SECONDS="${DRAIN_SECONDS:-60}"

echo "=================================================================="
echo " S3 Encryption Gateway — EMERGENCY CANARY ROLLBACK"
echo " Namespace        : ${NS}"
echo " TraefikService   : ${TS}"
echo " Stable backend   : ${STABLE_SVC} (weight → 100)"
echo " Canary backend   : ${CANARY_SVC} (weight → 0)"
echo "=================================================================="
echo ""
echo "STEP 1/3: Snapping traffic to 100 % stable ..."

kubectl -n "${NS}" patch traefikservice "${TS}" --type=merge \
  -p "{\"spec\":{\"weighted\":{\"services\":[
      {\"name\":\"${STABLE_SVC}\",\"port\":${PORT},\"weight\":100},
      {\"name\":\"${CANARY_SVC}\",\"port\":${PORT},\"weight\":0}
    ]}}}"

echo "         Traffic is now 100 % on stable, 0 % on canary."
echo ""
echo "STEP 2/3: Waiting ${DRAIN_SECONDS} s for in-flight canary requests to drain ..."
echo "         (Adjust DRAIN_SECONDS if your workload has longer requests.)"
sleep "${DRAIN_SECONDS}"

echo ""
echo "STEP 3/3: Removing canary release ..."
if helm status gw-canary -n "${NS}" &>/dev/null; then
  helm uninstall gw-canary -n "${NS}"
  echo "         helm release 'gw-canary' removed."
else
  echo "         Helm release 'gw-canary' not found — skipping uninstall."
  echo "         If the canary Deployment still exists, remove it manually:"
  echo "           kubectl delete deployment -n ${NS} -l track=canary"
fi

echo ""
echo "=================================================================="
echo " Rollback complete."
echo " Review canary pod logs for root-cause before the next canary attempt:"
echo "   kubectl logs -n ${NS} -l track=canary --previous"
echo "=================================================================="
