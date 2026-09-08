# PQC OpenClaw Fork

> **Post-quantum hardened** OpenClaw with side-channel-resilient
> cryptographic primitives, best-effort mlock-pinned wrap keys, and paper-grade
> verification of every claim.

[![CI: side-channel](https://github.com/WU123-ABC-Cell/pqc-openclaw/actions/workflows/pqc-side-channel.yml/badge.svg?branch=master)](.github/workflows/pqc-side-channel.yml)
[![CI: deploy E2E](https://github.com/WU123-ABC-Cell/pqc-openclaw/actions/workflows/pqc-deploy-e2e.yml/badge.svg?branch=master)](.github/workflows/pqc-deploy-e2e.yml)
[![Paper-grade](https://img.shields.io/badge/audit-paper--grade-blueviolet)](docs/security/pqc-whitepaper.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

A hardening fork of [OpenClaw](https://github.com/openclaw/openclaw) whose
verified PQC paths use ML-DSA, ML-KEM, and AES-256-GCM while preserving the
upstream client-facing API where documented. Forked from `openclaw/openclaw` and maintained independently
by [@WU123-ABC-Cell](https://github.com/WU123-ABC-Cell).

---

## What you get

- **Post-quantum signatures**: `ml-dsa-65` (NIST FIPS 204) and `ml-dsa-44`,
  `ml-dsa-87` for security/performance tradeoffs, alongside the
  Ed25519 fallback for legacy clients.
- **Post-quantum KEM**: `ml-kem-768` (NIST FIPS 203) and `ml-kem-512`,
  `ml-kem-1024` for hybrid KEX.
- **Best-effort wrap-key RAM pinning**: on supported Linux builds, the native
  addon calls `mlock(2)` for the 32-byte cached wrap key. This protects against
  swap, not core dumps. The production installer provisions a mode-0600 file;
  OS-keyring migration is an explicit operator step. See
  [docs/security/MLOCK.md](docs/security/MLOCK.md).
- **Constant-time crypto path**: every primitive is from
  [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum)
  v0.7.0. This fork's self-audit is at
  [docs/security/constant-time-audit.md](docs/security/constant-time-audit.md).
- **Empirically checked**: 14 checked-in cache-timing reports pass the
  integrity gate (`max |t| = 1.983`, threshold 4.5). The latest local gate also
  passed 275 focused tests, five deploy harnesses, a native 32-byte
  mlock/munlock roundtrip, and a complete sandbox install. The historical
  campaign covered 28 user-space/cache-hierarchy measurements and 129,200
  trials; these are separate evidence layers, not one combined test count.

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

# 2. Install the Node.js version pinned by .nvmrc
nvm install && nvm use
# Or: nvm use  (reads .nvmrc)

# 3. 1-command installer
sudo bash scripts/install-pqc.sh
# → installs to /opt/pqc-openclaw, creates a file-backed wrap key,
#   and renders the systemd unit

# 4. Verify the default file-backed deployment
bash scripts/healthcheck-pqc.sh --json --skip-keyring
# Expect: fail = 0. A warning means an optional capability is unavailable.
```

For a deeper walk-through, see [docs/USER_GUIDE.md](docs/USER_GUIDE.md).

## 5-line PQC example

```js
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { randomBytes } from "node:crypto";

const { publicKey, secretKey } = ml_dsa65.keygen(randomBytes(32));
const message = Buffer.from("hello pqc");
const sig = ml_dsa65.sign(message, secretKey);
const ok = ml_dsa65.verify(sig, message, publicKey);
console.log("verified:", ok); // → "verified: true"
```

Full examples live in [`examples/`](examples/).

## Repo layout

```
.
├── src/security/           PQC keyring, mlock, wrap key, audit log
│   ├── mlock-helper.ts    process hook + Linux native-addon fallback
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
│   ├── pqc-whitepaper.md       design, claims, limitations, and evidence
│   ├── constant-time-audit.md  308-line self-audit
│   ├── MLOCK.md                mlock design + validation + 4-step procedure
│   ├── OPERATIONS.md           On-call runbook (5 failure modes + back-up)
│   ├── MIGRATION.md           upstream → PQC fork step-by-step
│   ├── PAPER-SUBMISSION-CHECKLIST.md paper venue evidence index
│   ├── paper-reviewer-faq.md  12 Q&A for academic reviewers
│   ├── verification-log-2026-08-29-30.md  audit-trail of 28 ops × 0 leak
│   ├── ...
├── docker-compose.pqc.yml  Production-hardened container compose
└── .github/workflows/      3 self-contained PQC workflows
    ├── pqc-ci.yml              focused typecheck + unit/infra tests
    ├── pqc-side-channel.yml    native-addon + evidence-integrity gates
    └── pqc-deploy-e2e.yml      static, five harnesses, sandbox install
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
