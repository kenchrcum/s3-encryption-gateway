# V0.6-QA-1 — Performance Baseline Artefacts

This directory holds the committed v0.6 performance baseline corpus. See
[`docs/PERFORMANCE.md`](../../PERFORMANCE.md) for methodology, the public
baseline table, and how to interpret regression alerts.

## Files

| File | Purpose |
|---|---|
| `micro-baseline.txt` | `benchstat`-parseable output of the 19 tracked Go `Benchmark*` functions (see plan §5.3). Header lines starting with `#` record runner / Go version / commit SHA. |
| `macro-<provider>.json` | One file per local Testcontainers backend (`minio`, `garage`, `rustfs`, `seaweedfs`), schema v1 per plan §4.2. `runs[]` contains one object per load-test invocation (`Load_RangeRead`, `Load_Multipart`). |
| `slo-summary.md` | Latency × provider × operation table (§8) — renderable markdown for the docs page. |

## Regenerating

```bash
make bench-baseline        # micro + all four macros (~30-40 min on CI)
make bench-micro-baseline  # micro only
make bench-macro-minio     # one provider at a time
```

`bench-baseline` runs macros serially because Testcontainers consumes > 6 GB
RAM for four simultaneous providers (plan §9 risk 3). Prereqs: `docker`,
`jq`, `go ≥ 1.25`, `benchstat` (install via
`go install golang.org/x/perf/cmd/benchstat@latest`).

## Version pinning

Per-milestone archiving (plan §4.1) is deliberate: v0.7 will add
`docs/perf/v0.7-qa-1/` rather than overwriting this directory, so ADR
references that cite specific numbers (e.g. ADR 0010 "p99 MinIO < X ms")
remain stable across releases.
