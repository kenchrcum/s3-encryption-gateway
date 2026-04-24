#!/usr/bin/env bash
# docs/examples/canary/promote.sh
#
# Canary traffic weight promotion script.
# Patches the Traefik TraefikService to shift traffic weight from the stable
# release towards the canary release in configurable steps.
#
# USAGE:
#   ./promote.sh 5              # initial canary split (default start)
#   ./promote.sh 25             # first promotion step
#   ./promote.sh 50             # halfway
#   ./promote.sh 100            # full promotion — canary becomes stable
#   ./promote.sh --rollback     # snap back to 100 % stable, 0 % canary
#   ./promote.sh --step 30      # arbitrary weight (must be 0-100)
#
# ENVIRONMENT:
#   NAMESPACE        Kubernetes namespace (default: s3-gateway)
#   TRAEFIKSERVICE   Name of the TraefikService (default: gateway-weighted)
#   STABLE_SVC       Stable backend Service name (default: gw-stable-s3-encryption-gateway)
#   CANARY_SVC       Canary backend Service name (default: gw-canary-s3-encryption-gateway)
#   SVC_PORT         Service port (default: 80)
#
# AFTER FULL PROMOTION (weight=100):
#   1. Run a role swap: the canary release becomes the new stable.
#      - helm upgrade gw-stable ... --values values-canary-stable.yaml
#        (with the new image tag)
#      - Update traefikservice.yaml to reference the new stable Service name.
#      - helm uninstall gw-canary
#   2. Advance the active KMS key version (CFG-1 rotation procedure).
#
# See docs/OPS_DEPLOYMENT.md §4 for the complete procedure.
set -euo pipefail

NS="${NAMESPACE:-s3-gateway}"
TS="${TRAEFIKSERVICE:-gateway-weighted}"
STABLE_SVC="${STABLE_SVC:-gw-stable-s3-encryption-gateway}"
CANARY_SVC="${CANARY_SVC:-gw-canary-s3-encryption-gateway}"
PORT="${SVC_PORT:-80}"

# ── Parse arguments ──────────────────────────────────────────────────────────
CANARY_WEIGHT=""
case "${1:-}" in
  --rollback)
    CANARY_WEIGHT=0
    ;;
  --step)
    CANARY_WEIGHT="${2:?--step requires a numeric weight argument (0-100)}"
    ;;
  5|25|50|100)
    CANARY_WEIGHT="$1"
    ;;
  "")
    echo "Usage: $0 {5|25|50|100|--rollback|--step N}" >&2
    echo "" >&2
    echo "  Predefined steps: 5 → 25 → 50 → 100" >&2
    echo "  Rollback:         --rollback (snaps canary to 0 %)" >&2
    echo "  Custom:           --step N   (N must be 0-100)" >&2
    exit 2
    ;;
  *)
    echo "ERROR: Unknown argument '${1}'. Use 5, 25, 50, 100, --rollback, or --step N." >&2
    exit 2
    ;;
esac

STABLE_WEIGHT=$((100 - CANARY_WEIGHT))

echo "=================================================================="
echo " S3 Encryption Gateway — Canary Promotion"
echo " Namespace        : ${NS}"
echo " TraefikService   : ${TS}"
echo " Stable backend   : ${STABLE_SVC} (weight → ${STABLE_WEIGHT})"
echo " Canary backend   : ${CANARY_SVC} (weight → ${CANARY_WEIGHT})"
echo "=================================================================="

# ── Patch the TraefikService ─────────────────────────────────────────────────
kubectl -n "${NS}" patch traefikservice "${TS}" --type=merge \
  -p "{\"spec\":{\"weighted\":{\"services\":[
      {\"name\":\"${STABLE_SVC}\",\"port\":${PORT},\"weight\":${STABLE_WEIGHT}},
      {\"name\":\"${CANARY_SVC}\",\"port\":${PORT},\"weight\":${CANARY_WEIGHT}}
    ]}}}"

echo ""
echo "  Canary weight → ${CANARY_WEIGHT} %  |  Stable weight → ${STABLE_WEIGHT} %"
echo ""

if [[ "$CANARY_WEIGHT" -eq 0 ]]; then
  echo "  Rollback complete. Canary traffic is 0 %."
  echo "  To remove the canary release after draining:"
  echo "    helm uninstall gw-canary -n ${NS}"
elif [[ "$CANARY_WEIGHT" -eq 100 ]]; then
  echo "  Full promotion complete. 100 % traffic on canary."
  echo ""
  echo "  Next steps:"
  echo "    1. Observe SLIs for a final soak window (≥ 15 min)."
  echo "    2. Perform the role-swap: update gw-stable to the new image."
  echo "    3. Advance the KMS key version (CFG-1 rotation procedure)."
  echo "    4. helm uninstall gw-canary -n ${NS}"
else
  echo "  Observe canary SLI for the soak window before the next step."
  echo ""
  echo "  Prometheus query (canary p99 latency):"
  echo "    histogram_quantile(0.99, rate(s3_gateway_request_duration_seconds_bucket{track=\"canary\"}[5m]))"
  echo ""
  NEXT_WEIGHTS=(5 25 50 100)
  for w in "${NEXT_WEIGHTS[@]}"; do
    if [[ $w -gt $CANARY_WEIGHT ]]; then
      echo "  Next step: $0 ${w}"
      break
    fi
  done
  echo "  Rollback:  $0 --rollback"
fi
