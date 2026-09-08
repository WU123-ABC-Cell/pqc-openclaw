# Paper submission evidence checklist

> **Current snapshot (2026-09-07)**: master `d3b940a21e`. The three PQC
> workflow files are restored and self-contained. Hosted GitHub Actions is not
> green: runs in the private repository fail before runner allocation, with no
> job steps or logs.

## 1. Current local verification

The latest local gate completed:

- `pnpm tsgo:core`;
- 275 focused Vitest tests across the PQC unit and infrastructure suites;
- all 18 focused mlock-helper tests;
- a real Linux native-addon 32-byte `mlock`/`munlock` roundtrip;
- five deploy harnesses under `scripts/pqc-e2e/`;
- a complete isolated `--sandbox-root` install, build, and artifact check; and
- integrity validation of all 14 checked-in cache-timing reports.

These are separate validation layers. Do not add them into a synthetic
"invariants" total, and do not describe local results as equivalent to hosted
CI green.

## 2. Evidence index

| Claim or control                  | Current evidence                                                      |
| --------------------------------- | --------------------------------------------------------------------- |
| ML-DSA / ML-KEM integration       | focused tests selected by `.github/workflows/pqc-ci.yml`              |
| Wrap-key lifecycle                | `src/security/*keyring*.test.ts`, `src/security/mlock-helper.test.ts` |
| Linux swap protection             | `pnpm build:native` plus native 32-byte lock/unlock roundtrip         |
| Historical cache-timing summaries | `docs/security/ct-reports/*/report.json`                              |
| Evidence integrity                | `node scripts/check-pqc-cache-timing-evidence.mjs`                    |
| Deployment scripts                | five harnesses under `scripts/pqc-e2e/`                               |
| Full installer workspace          | `.github/workflows/pqc-deploy-e2e.yml` sandbox install job            |
| Threats and limitations           | `docs/security/constant-time-audit.md`, `docs/security/MLOCK.md`      |

The 14 JSON reports are retained historical measurements, not fresh
benchmarks of the current checkout. Their recorded maximum is `|t| = 1.983`
against threshold 4.5. This means the recorded experiment did not observe a
statistically significant difference above its chosen threshold; it does not
prove constant-time behavior or absence of side channels.

## 3. Workflow status

| Workflow               | Repository gate                                                      |
| ---------------------- | -------------------------------------------------------------------- |
| `pqc-ci.yml`           | core typecheck plus nine focused test files                          |
| `pqc-side-channel.yml` | native addon build/roundtrip plus timing-evidence integrity          |
| `pqc-deploy-e2e.yml`   | static checks, five deploy harnesses, complete sandbox install/build |

All three use read-only `contents` permissions, pinned action SHAs, and no
`continue-on-error` gates. The remaining hosted-run blocker is external to
workflow steps: the private repository currently receives no runner assignment.
Investigate Actions permissions, quota, billing, and organization policy before
claiming CI success.

## 4. Claims that are safe to make

- The recorded 2026-08 timing campaign covered 14 user-space operations and 14
  cache-hierarchy operation reports across 129,200 historical trials.
- All 14 retained cache-timing reports pass the current integrity checker; the
  maximum recorded absolute t-statistic is 1.983 under a 4.5 threshold.
- The Linux native addon has completed a real mlock/munlock roundtrip locally.
- The installer and five deployment harnesses completed local isolated checks.
- The implementation has a repository self-audit and an explicit limitations
  list.

## 5. Claims that are not safe to make

- "CI is green" while hosted jobs have no runner assignment.
- "No timing leak" or "verified constant-time" based only on thresholded,
  environment-specific historical measurements.
- `mlock` prevents core dumps. It protects against swap only.
- Node 24.15.0 provides `process.mlock`; it does not.
- The installer automatically writes an OS keyring or a cron entry. Linux uses
  a systemd backup timer; other schedulers remain operator-managed.
- The project has received an independent third-party cryptographic audit or
  FIPS 140-3 validation.

## 6. Audit-grade backlog

- independent third-party cryptographic review;
- fresh reproducible timing measurements for the current checkout;
- per-operation cache tests and active PRIME+PROBE / FLUSH+RELOAD work;
- hardware counters, EM/power analysis, and fault injection;
- addon-owned page-aligned secure allocation with core-dump exclusion;
- Linux arm64, macOS, and Windows secure-memory backend/build validation; and
- successful hosted workflow runs on assigned runners.

## 7. Historical note

Earlier snapshots used totals such as `301/301`, `220`, or `206` and referenced
an external `pqc-fork-scripts/` directory. Those values describe dated local
campaigns and must not be presented as the current aggregate gate. Current
repository-owned evidence lives under `docs/security/ct-reports/`,
`scripts/pqc-e2e/`, and the three checked-in workflows.
