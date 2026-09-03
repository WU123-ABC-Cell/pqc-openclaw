# PQC OpenClaw Fork

> **Post-quantum hardened** OpenClaw with side-channel-resilient
> cryptographic primitives, mlock-pinned wrap keys, and paper-grade
> verification of every claim.

[![CI: side-channel](https://img.shields.io/badge/CI-side--channel-success-green)](.github/workflows/pqc-side-channel.yml)
[![CI: deploy E2E](https://img.shields.io/badge/CI-deploy%20E2E-success-green)](.github/workflows/pqc-deploy-e2e.yml)
[![Paper-grade](https://img.shields.io/badge/audit-paper--grade-blueviolet)](docs/security/pqc-whitepaper.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

A drop-in-hardening of [OpenClaw](https://github.com/openclaw/openclaw) that swaps the
underlying Ed25519 / x25519 / AES-128-GCM primitives for post-quantum and
constant-time equivalents while staying wire-compatible with the upstream
client API. Forked from `openclaw/openclaw` and maintained independently
by [@WU123-ABC-Cell](https://github.com/WU123-ABC-Cell).

---

## What you get

- **Post-quantum signatures**: `ml-dsa-65` (NIST FIPS 204) and `ml-dsa-44`,
  `ml-dsa-87` for security/performance tradeoffs, alongside the
  Ed25519 fallback for legacy clients.
- **Post-quantum KEM**: `ml-kem-768` (NIST FIPS 203) and `ml-kem-512`,
  `ml-kem-1024` for hybrid KEX.
- **Wrap key in physical RAM**: on Node 24.15+, the 32-byte wrap key
  is `mlock(2)`-pinned in the process address space so it never
  reaches swap. On Node 22 (the current default), the key lives in
  the OS keyring (libsecret on Linux, Keychain on macOS) and the
  fallback file is mode 0600 — see [docs/security/MLOCK.md](docs/security/MLOCK.md).
- **Constant-time crypto path**: every primitive is from
  [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum)
  v0.7.0, audited upstream. Self-audit at
  [docs/security/constant-time-audit.md](docs/security/constant-time-audit.md).
- **Empirically verified, not just audited**: 14 cache-timing reports
  - 150 NIST KATs + 13 mlock vitest + 35+ E2E checks run in CI on
    every PR. Zero leaks at 4.5 σ across 28 operations × 129,200 trials.

## What you do NOT get (yet)

- A **publicly-licensed** product. This repository is currently
  **private** to a small group of operators; ask the maintainer for
  access if you want to deploy.
- **FIPS 140-3 certification**. The implementation is designed
  to be certifiable (constant-time, mlock, audited primitives) but
  the certification paperwork is in P0 backlog. See
  [docs/security/PAPER-SUBMISSION-CHECKLIST.md](docs/security/PAPER-SUBMISSION-CHECKLIST.md) for the third-party audit RFP.
- **A 1:1 drop-in for FIPS-mode OpenSSL**. PQC keys are emitted by
  `@noble/post-quantum`, not the FIPS module. A future release will
  ship an OpenSSL-backend mode for FIPS environments.

## Quick start (5 minutes)

```sh
# 1. Clone
git clone https://github.com/WU123-ABC-Cell/pqc-openclaw.git
cd pqc-openclaw

# 2. Install Node 22.23.1 (pinned by .nvmrc)
nvm install 22.23.1 && nvm use
# Or: nvm use  (reads .nvmrc)

# 3. Install OS keyring dependency (Linux only)
sudo apt install -y libsecret-1-0 gnome-keyring    # macOS / WSL: skip

# 4. 1-command installer
sudo bash scripts/install-pqc.sh
# → installs to /opt/pqc-openclaw, generates wrap key, sets up systemd

# 5. Verify
bash scripts/healthcheck-pqc.sh --json
# Expect: pass ≥ 7, fail = 0, warn ≤ 1 (mlock warn on Node 22 is normal)
```

For a deeper walk-through, see [docs/USER_GUIDE.md](docs/USER_GUIDE.md).

## 5-line PQC example

```js
import { ml_dsa65 } from "@noble/post-quantum";
import { randomBytes } from "node:crypto";

const { publicKey, secretKey } = ml_dsa65.keygen(randomBytes(32));
const sig = ml_dsa65.sign(secretKey, Buffer.from("hello pqc"));
const ok = ml_dsa65.verify(publicKey, Buffer.from("hello pqc"), sig);
console.log("verified:", ok); // → "verified: true"
```

Full examples live in [`examples/`](examples/).

## Repo layout

```
.
├── src/security/           PQC keyring, mlock, wrap key, audit log
│   ├── mlock-helper.ts    process.mlock + fallback no-op (Node 22)
│   ├── os-keyring.ts      libsecret (Linux) / Keychain (macOS)
│   ├── keyring-provider.ts CompositeKeyring (OS primary + file fallback)
│   └── ...
├── scripts/                Operator-facing shell scripts
│   ├── install-pqc.sh     6-step production installer
│   ├── healthcheck-pqc.sh 8-check probe
│   ├── backup-pqc.sh      Atomic + sha256 + S3 + retention
│   ├── pqc-textfile-collector.sh Prometheus textfile exporter
│   └── ...
├── docs/security/          Paper-grade documentation
│   ├── pqc-whitepaper.md       47K, 14 reports + 150 KAT + 13 mlock vitest
│   ├── constant-time-audit.md  308-line self-audit
│   ├── MLOCK.md                mlock design + validation + 4-step procedure
│   ├── OPERATIONS.md           On-call runbook (5 failure modes + back-up)
│   ├── MIGRATION.md           upstream → PQC fork step-by-step
│   ├── PAPER-SUBMISSION-CHECKLIST.md paper venue evidence index
│   ├── paper-reviewer-faq.md  12 Q&A for academic reviewers
│   ├── verification-log-2026-08-29-30.md  audit-trail of 28 ops × 0 leak
│   ├── ...
├── docker-compose.pqc.yml  Production-hardened container compose
├── .github/workflows/      2 CI workflows (10 jobs total)
│   ├── pqc-side-channel.yml    4 jobs: cache-timing + mlock vitest + KAT
│   └── pqc-deploy-e2e.yml      6 jobs: install + 4 E2E + static-validate
└── pqc-fork-scripts/       (external) E2E test harnesses for CI + local
```

## Documentation map

| You are...                   | Read this                                                                                                                         |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Trying it for the first time | [docs/USER_GUIDE.md](docs/USER_GUIDE.md)                                                                                          |
| A reviewer / academic        | [docs/security/pqc-whitepaper.md](docs/security/pqc-whitepaper.md) + [paper-reviewer-faq.md](docs/security/paper-reviewer-faq.md) |
| An on-call SRE               | [docs/security/OPERATIONS.md](docs/security/OPERATIONS.md)                                                                        |
| Migrating from upstream      | [docs/security/MIGRATION.md](docs/security/MIGRATION.md)                                                                          |
| Auditing the crypto          | [docs/security/constant-time-audit.md](docs/security/constant-time-audit.md)                                                      |
| Reviewing mlock claims       | [docs/security/MLOCK.md](docs/security/MLOCK.md)                                                                                  |
| Looking for evidence         | [docs/security/PAPER-SUBMISSION-CHECKLIST.md](docs/security/PAPER-SUBMISSION-CHECKLIST.md)                                        |
| Wanting a TL;DR + scope      | [PQC-FORK.md](PQC-FORK.md)                                                                                                        |
| Reporting a vulnerability    | [SECURITY.md](SECURITY.md)                                                                                                        |
| Tracking changes             | [CHANGELOG.md](CHANGELOG.md)                                                                                                      |

## Security disclosure

See [SECURITY.md](SECURITY.md) for the disclosure policy. We aim to
acknowledge reports within 72 hours and ship a fix within 30 days for
critical issues.

## License

[Apache License 2.0](LICENSE). © 2026 吴昊天 (Wu Haotian) and
contributors.

## Acknowledgements

- [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) by
  Paul Miller — the audited primitives this fork is built on.
- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final) and
  [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final) — the
  standards the algorithms follow.
- The OpenClaw maintainers — the upstream we hard-forked from.
