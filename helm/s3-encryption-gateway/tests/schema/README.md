# Schema Test Suite

This directory contains the positive and negative test cases for the
`values.schema.json` JSON Schema that validates Helm values for the
S3 Encryption Gateway chart.

## File naming conventions

| Pattern | Purpose |
|---------|---------|
| `good-*.yaml` | Positive tests — must be **accepted** by `helm lint` |
| `bad-*.yaml`  | Negative tests — must be **rejected** by `helm lint` with the error substring documented in the file header |

## Running tests

```bash
# Run all negative tests (verifies schema catches bad values):
bash helm/s3-encryption-gateway/tests/schema/run-negative.sh

# Run all positive tests manually:
for f in helm/s3-encryption-gateway/tests/schema/good-*.yaml; do
  echo -n "$f: "
  helm lint helm/s3-encryption-gateway -f "$f" 2>&1 | tail -1
done

# Run the drift check (requires helm-values-schema-json plugin):
bash helm/s3-encryption-gateway/scripts/schema-drift.sh
```

## Adding a new rule + test pair

1. Add the constraint to `helm/s3-encryption-gateway/values.schema.json`
   (under `properties`, `$defs`, or `allOf` invariants as appropriate).

2. Create a `bad-<rule-name>.yaml` file containing the **minimal** values
   fragment that triggers exactly that one rule:
   ```yaml
   # bad-my-rule.yaml — short description of what rule this violates.
   # Expected error substring: "the exact substring helm lint will print"
   myField:
     badValue: ...
   ```

3. Create a `good-<rule-name>.yaml` file containing values that correctly
   satisfy the new rule (to prevent false positives).

4. Run the harness to verify both tests behave correctly:
   ```bash
   bash helm/s3-encryption-gateway/tests/schema/run-negative.sh
   helm lint helm/s3-encryption-gateway -f tests/schema/good-<rule-name>.yaml
   ```

5. The CI `schema-negative` job (`.github/workflows/helm-test.yml`) will
   automatically pick up all `bad-*.yaml` files — no CI changes needed.

## Invariant catalogue

| Invariant | Description | Test files |
|-----------|-------------|------------|
| I1 | `track` → external Valkey required | `bad-track-with-valkey.yaml`, `bad-track-no-valkey-addr.yaml`, `good-track-with-external-valkey.yaml` |
| I2 | `ingress.enabled` + `ingress.traefik.enabled` are mutually exclusive | `bad-both-ingress.yaml`, `good-ingress-only.yaml`, `good-traefik-only.yaml` |
| I3 | `ingress.traefik.weighted.enabled` → `ingress.traefik.enabled` | `bad-weighted-no-traefik.yaml`, `good-weighted-with-traefik.yaml` |
| I4 | Weighted services weights sum = 100 | Template-time only (`templates/validate.yaml`) — draft-07 cannot express sum constraints declaratively |
| I5 | `keyManager.enabled=true` → valid provider enum | `bad-keymanager-no-provider.yaml`, `good-keymanager-cosmian.yaml` |
| I7 | `tls.enabled=true` + `useCertManager=false` → certFile + keyFile required | `good-tls-with-certmanager.yaml` |
