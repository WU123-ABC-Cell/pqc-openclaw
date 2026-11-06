# Cache-timing evidence

This directory contains the 14 report summaries used by the PQC fork's
cache-timing evidence gate: AES-GCM wrap/unwrap plus ML-DSA and ML-KEM
operations across the supported parameter sets.

The reports are retained summaries from a 2026-08 measurement campaign, not
fresh benchmarks of the current checkout. CI checks their stored shape and
threshold values with:

```bash
node scripts/check-pqc-cache-timing-evidence.mjs
```

The checker requires all 14 named reports, 20 samples per class, nine cache
events per report, `overall.leak === false`, and `|t| < 4.5` for every event.
It does not recompute statistics from raw samples, authenticate report origins,
or run the measurements. Raw callgrind output and the original runners under
the external `pqc-fork-scripts/` directory are not tracked in this repository;
a clean clone cannot reproduce the historical campaign from these files alone.

Changes to cryptographic hot paths need a new, separately documented
measurement campaign with pinned runner source, exact code and dependency
versions, raw observations, commands, environment, and analysis before making
a fresh timing claim. The retained summaries must not be presented as that
new evidence or as proof of constant-time behavior.
