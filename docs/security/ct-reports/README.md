# Cache-timing evidence

This directory contains the 14 report summaries used by the PQC fork's
cache-timing evidence gate: AES-GCM wrap/unwrap plus ML-DSA and ML-KEM
operations across the supported parameter sets.

The reports are fixed measurement evidence, not fresh benchmarks of the
current checkout. CI validates their inventory and integrity with:

```bash
node scripts/check-pqc-cache-timing-evidence.mjs
```

The checker requires all 14 named reports, 20 samples per class, nine cache
events per report, `overall.leak === false`, and `|t| < 4.5` for every event.
Changes to cryptographic hot paths still require regenerating these reports
with the documented measurement procedure before updating the evidence.
