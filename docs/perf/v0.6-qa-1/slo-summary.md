# V0.6-QA-1 — SLO Annex

Values marked **TBD** are placeholders pending the first green nightly
`performance-baseline` workflow run on `main` (DoD, plan §10). The
**structure** of this table is committed so that downstream consumers
(ADR 0010, PERF-2 open Q2, the README Performance section) can wire their
references before the numbers land.

Last updated: TBD.
Runner class: `github-ubuntu-latest` (2 vCPU, 7 GB) — plan §9 risk 6.

## Operation × Provider latency matrix (p95 / p99 in ms)

| Operation | MinIO p95/p99 | Garage p95/p99 | RustFS p95/p99 | SeaweedFS p95/p99 |
|---|---|---|---|---|
| `Load_RangeRead` (50 MiB obj, 64 KiB ranges, 10 workers, 25 QPS) | TBD / TBD | TBD / TBD | TBD / TBD | TBD / TBD |
| `Load_Multipart` (50 MiB obj, 10 MiB parts, 10 workers) | TBD / TBD | TBD / TBD | TBD / TBD | TBD / TBD |

## Throughput matrix (MB/s)

| Operation | MinIO | Garage | RustFS | SeaweedFS |
|---|---|---|---|---|
| `Load_RangeRead` | TBD | TBD | TBD | TBD |
| `Load_Multipart` | TBD | TBD | TBD | TBD |

## Consumers

- **ADR 0010** (backend retry policy, circuit-breaker decision input) reads the
  p99 column to decide per-provider fallback cost.
  See [`docs/adr/0010-backend-retry-policy.md`](../../adr/0010-backend-retry-policy.md).
- **V0.6-PERF-2 Q2** (retry policy defaults) reads the p95 column.
- **README Performance section** links here for operator sizing estimates.
- **v0.7 / v1.0 roadmap** uses this as the baseline to beat.

## Regenerating

`make bench-baseline` re-runs the macro soak against every local provider
and overwrites `macro-<provider>.json`. Renumbering this table from those
files is scripted in the docs renderer (see `docs/PERFORMANCE.md`
§"How to regenerate").
