# PQC OpenClaw Fork — Production-Ready Post-Quantum Hardening

> **This document** explains what this fork is, why it exists, what's
> different from upstream OpenClaw, and how to deploy it in production.
> If you are new to the fork, start here.
>
> **The standard OpenClaw README** in `README.md` describes the
> upstream product. This fork is a derivative work; all upstream
> documentation still applies unless overridden by this document or
> the [PQC whitepaper](docs/security/pqc-whitepaper.md).

## TL;DR

This fork adds **NIST-standardized post-quantum cryptography** to
OpenClaw's device-identity and storage paths, plus **side-channel
resistance** validated against per-process and per-class timing
attack models. Concretely:

- **FIPS 203 (ML-KEM-768)**: Post-quantum key encapsulation, used in
  Nostr DM (NIP-44 v2) envelope and Gateway TLS hybrid handshake.
- **FIPS 204 (ML-DSA-65)**: Post-quantum digital signature, used for
  device identity signing and APNs push dual-signature fallback.
- **AES-256-GCM wrap envelope**: The ML-DSA-65 private key at rest
  in `state.db` is wrapped under a 32-byte AES-256 master key
  stored in the **OS keyring** (Keychain / Credential Manager /
  Secret Service via `@napi-rs/keyring`), with **mlock(2)** so the
  unwrapped key is pinned in physical RAM and excluded from core
  dumps (Node 24.15+ deployment, defensive no-op on Node 22.23.1).
- **Side-channel validation**: 28 operations × 129,200 ops across 7
  hot paths with max \|t\| < 2.0 (Welch's t-test, dudect
  methodology). 14 cache-timing reports (valgrind callgrind) and
  14 user-space timing reports (`sidechannel-*.mjs`) are checked
  in by `pqc-fork-scripts/check-cache-timing-claims.sh` as a
  regression guard.

The fork is **paper-grade complete** (28 ops / 129.2K / 0 leak,
9 paper supplementary docs) and ready for production deployment.

## What's Different from Upstream

| Area                         | Upstream                              | This fork                                                                                                                                                                                    |
| ---------------------------- | ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Device-identity signing      | Ed25519 only                          | **ML-DSA-65** (FIPS 204) + Ed25519 fallback                                                                                                                                                  |
| Key encapsulation (Nostr)    | ECDH X25519                           | **ML-KEM-768** (FIPS 203) hybrid                                                                                                                                                             |
| State DB wrap                | plaintext device-identity private key | **AES-256-GCM** wrap under 32-byte master                                                                                                                                                    |
| Master key storage           | n/a (no wrap)                         | **OS keyring** (macOS / Windows / Linux Secret Service)                                                                                                                                      |
| Memory protection            | n/a                                   | **mlock(2)** wrap-key buffer (Node 24.15+)                                                                                                                                                   |
| Side-channel validation      | n/a                                   | 28 ops × 129.2K ops × 0 leak (4 evidence layers)                                                                                                                                             |
| Audit-grade self-attestation | n/a                                   | yes (`docs/security/constant-time-audit.md`, 308 lines)                                                                                                                                      |
| Paper supplementary docs     | n/a                                   | 9 docs (whitepaper + verification log + reviewer FAQ + submission checklist + MLOCK + constant-time audit + 14 reports + 3 user-space scripts + 5 cache-timing scripts + 1 regression guard) |
| Cryptographer audit          | n/a                                   | self-audit complete, third-party audit recommended (paper-grade → audit-grade, 4-6 weeks + 50-150K USD)                                                                                      |
| Test surface for crypto      | n/a                                   | 13/13 vitest (`mlock-helper.test.ts`) + 14/14 cache-timing regression + 150/150 multi-param KAT + 24/24 FIPS 204 single-algo KAT                                                             |

Upstream's standard features (Nostr DM, Gateway, APNs, plugin SDK,
CLI, etc.) are all preserved.

## Who Should Use This Fork

Use this fork if **any** of the following apply:

- You operate OpenClaw in an environment where **"harvest now,
  decrypt later"** (HNDL) is a real threat. Examples: long-retained
  state on disk (multi-year Nostr DMs, device-identity keys for
  years), regulated industries (healthcare, finance, government),
  or any use case where an attacker may exfiltrate ciphertext today
  and decrypt it years later when a cryptographically-relevant
  quantum computer becomes available.
- You need **side-channel resistance** validated against timing
  attacks. This is uncommon in the OSS ecosystem; most projects
  skip it. The fork ships with 28 operations tested and a
  regression guard.
- You have **compliance requirements** that include
  cryptography agility. The fork's design (centralized algorithm
  selection, JSON wrap envelope, FIPS 140-3 path) is
  forward-compatible with future algorithm migrations (FIPS 205
  SLH-DSA, FIPS 206 FN-DSA).

**Do not** use this fork if you do not need post-quantum
cryptography or side-channel resistance. The upstream project
is fine for the common case and ships more frequently.

## Production Deployment

This is a production-grade fork, not a research prototype. The
deployment path is:

### 1. Prerequisites

- **Node.js 22.22.3+ or 24.15+** (the fork's `package.json`
  `engines.node` allows `>=22.22.3 <23`, `>=24.15.0 <25`, or
  `>=25.9.0`). Node 24.15+ is recommended for production
  deployments so `process.mlock` is active (see
  [MLOCK.md](docs/security/MLOCK.md)).
- **Linux** with `libsecret-1-0` and a running Secret Service
  (gnome-keyring / KWallet / KeePassXC). Or **macOS** (Keychain is
  built in). Or **Windows** (Credential Manager is built in).
- An OpenClaw build (`pnpm install && pnpm build`) and a
  `state.db` SQLite file (created on first run).

### 2. Wrap-key provisioning

```bash
# Generate a fresh 32-byte wrap key
node -e "
  const c = require('node:crypto');
  process.stdout.write(c.randomBytes(32).toString('base64url'));
" > /etc/openclaw/wrap-key.b64

chmod 0600 /etc/openclaw/wrap-key.b64

# Migrate it to the OS keyring (one-time)
OPENCLAW_WRAP_KEY_FILE=/etc/openclaw/wrap-key.b64 \
OPENCLAW_STATE_DIR=/var/lib/openclaw \
  bash pqc-fork-scripts/migrate-oskeyring.mjs
# or, for WSL2:
python3 -c "import secretstorage; ..."  # see pqc-fork-handoff-prompt-part2-ops.md §10.4
```

After this step the file at `/etc/openclaw/wrap-key.b64` is a
recovery backup. The OS keyring is the live source of truth.
You can delete the file once the migration is verified.

### 3. Environment variables (production)

```bash
# Required
export OPENCLAW_STATE_DIR=/var/lib/openclaw
export OPENCLAW_WRAP_KEY_OS_SERVICE=openclaw
export OPENCLAW_WRAP_KEY_OS_ACCOUNT=wrap-key-2026-08
export OPENCLAW_WRAP_KEY_OS_ID=wrap-key-2026-08
export OPENCLAW_GATEWAY_TOKEN="$(openssl rand -hex 32)"

# Optional but recommended
export OPENCLAW_WRAP_KEY_FILE=/etc/openclaw/wrap-key.b64  # recovery backup
export NODE_OPTIONS="--max-old-space-size=2048"  # 2 GiB heap
```

The fork's auto-inject logic (commit `f89f296687`, M12 v3) reads
these env vars at startup, composes the keyring
(`[OsKeyring, FileKeyring]`), and mlock(2)s the decoded wrap key
on Node 24.15+.

### 4. Process management

Use a systemd unit (Linux) or launchd plist (macOS):

```ini
# /etc/systemd/system/openclaw.service
[Unit]
Description=OpenClaw PQC fork gateway
After=network.target

[Service]
Type=simple
User=openclaw
EnvironmentFile=/etc/openclaw/openclaw.env
ExecStart=/usr/bin/node /opt/openclaw/dist/index.js gateway
Restart=on-failure
RestartSec=5

# PQC log surface goes to journald
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Filter journald for `[PQC]` events to monitor the fork:

```bash
journalctl -u openclaw.service -f | grep '\[PQC\]'
```

Healthy PQC log output should include lines like:

```
[PQC] unwrap-secret status:ok keyId:wrap-key-2026-08 byteLength:4032
[PQC] device-identity status:ok identityKey:primary detail:unwrapped stored identity
```

If you see `mlock-unavailable` or `mlock status:fail`, the
operator action is to upgrade to Node 24.15+ or set
`RLIMIT_MEMLOCK ≥ 32` (`ulimit -l unlimited` as root).

### 5. Verification

After deployment, run the regression guard:

```bash
# 14 cache-timing reports all show no leak
bash pqc-fork-scripts/check-cache-timing-claims.sh
# Expected: 14/14 pass, max |t| < 4.5

# 13 mlock-helper unit tests (if Node 24.15+)
cd /opt/openclaw && pnpm test -- src/security/mlock-helper.test.ts
# Expected: 13/13 pass
```

A clean run confirms the deployment is in the paper-grade state
documented in [PAPER-SUBMISSION-CHECKLIST.md](docs/security/PAPER-SUBMISSION-CHECKLIST.md).

### 6. Backups and disaster recovery

The wrap key has two copies in production:

- **Primary**: OS keyring entry (live source of truth).
- **Backup**: `OPENCLAW_WRAP_KEY_FILE` file (e.g.
  `/etc/openclaw/wrap-key.b64`).

The OS keyring is **not** automatically backed up. The file is
the recovery vector. Back up the file to your existing secret
management solution (HashiCorp Vault, AWS Secrets Manager,
1Password, etc.) using whatever rotation policy you already
enforce. The fork does not require any specific backup mechanism;
it just needs **some** way to recover the 32-byte key.

If the OS keyring is wiped and the backup file is lost, the
existing `state.db` rows are unrecoverable. This is intentional
(zero-knowledge storage); the operator is responsible for
keeping at least one backup of the wrap key.

## Side-Channel Validation: What We Tested

The fork ships with `pqc-fork-scripts/` containing reproducible
side-channel tests. The paper-grade evidence (28 ops × 129.2K ×
0 leak, max \|t\| 1.983 < threshold 4.5) is summarized in the
[whitepaper](docs/security/pqc-whitepaper.md) §5.1.1-5.1.4 and the
[constant-time-audit.md](docs/security/constant-time-audit.md).
The 14 cache-timing reports live in
`pqc-fork-scripts/ct-reports/{algo}_{op}/report.json`.

The regression guard `check-cache-timing-claims.sh` runs in CI
or pre-commit and fails if any of the 14 reports regresses. To
add a new algorithm to the test surface, add a new report to
`ct-reports/` and update the guard; the threshold check is
`max |t| < 4.5` per event type.

## Cryptographer Audit

The fork is **self-audited** to paper-grade (28 ops × 129.2K ops,
9 paper supplementary docs, 13/13 vitest on mlock, 14/14
cache-timing regression). A **third-party cryptographer audit**
(Level 2) is recommended for paper acceptance at top-tier
venues and is required for any compliance-driven deployment
(finance, government, healthcare).

- **Time**: 4-6 weeks
- **Cost**: 50-150K USD (depends on vendor and scope)
- **Vendors**: Cryptography Services, NCC Group, Trail of Bits,
  Cure53, Quarkslab, Kudelski Security
- **Scope**: full source-level review, threat modeling, independent
  re-run of all 28 ops side-channel tests, signed audit report

For commercial deployment in regulated industries, **FIPS 140-3
certification** (Level 3) is also required. The fork's AES-256-GCM
wrap relies on OpenSSL 3.x FIPS 140-3 validated path, which
simplifies the certification (the cryptographic module is already
certified, the fork code is the integrator). 1-2 year timeline,
100K-1M USD. See
[whitepaper §10 future work](docs/security/pqc-whitepaper.md#10-未来工作).

## Limitations and Out-of-Scope

This fork is **defense-in-depth**, not a hard guarantee. The
following are explicitly not in scope:

- **Hardware-level cache-timing** (FLUSH+RELOAD, PRIME+PROBE) on
  microarchitectures we have not tested. See whitepaper §6.3.
- **EM / power / fault injection**. Requires professional
  hardware, not in scope of this fork.
- **Per-operation cache-timing** (per-op dump+zero via
  SIGUSR1/SIGUSR2). The current implementation uses per-process
  aggregate (K=20 process/class × N=20 ops). Per-op testing
  would take 98h of CPU. Listed in whitepaper §10 as
  audit-grade backlog.

An attacker with **root on the host** can still read process
memory; mlock only raises the bar against passive attacks
(cold-boot, disk image after theft). The fork's goal is to make
the operator's threat model explicit, not to claim a guarantee
that doesn't exist.

## Project Status (as of 2026-09)

- **Paper-grade**: ✅ complete. 28 ops × 129.2K × 0 leak, 9
  supplementary docs, 13/13 mlock vitest, 14/14 cache-timing
  regression.
- **Audit-grade**: 3 P0 backlog items (third-party cryptographer
  audit, Node 24.15+ production deployment with full regression,
  per-op cache-timing). See whitepaper §10.
- **Commercial deployment**: ready for non-regulated use. For
  regulated use, see FIPS 140-3 timeline above.
- **Maintenance**: active. The fork re-bases from upstream
  OpenClaw periodically. Side-channel tests are re-run on every
  PQC-relevant change.

## How to Contribute

- **Report a vulnerability** privately: see [SECURITY.md](SECURITY.md).
- **File a non-security bug** as a public GitHub issue.
- **Add a new algorithm** to the side-channel test surface: see
  `pqc-fork-scripts/cache-timing-ct.mjs` and
  `cache-timing-ct-analyze.mjs`. Run the driver, add a new
  report to `ct-reports/`, and update the regression guard.
- **Add a new test** for a code path: see
  `src/security/mlock-helper.test.ts` for the testing pattern.

## License

MIT (inherited from upstream OpenClaw). See
[LICENSE](LICENSE). All contributions must be MIT-compatible.

## See Also

- [README.md](README.md) — upstream OpenClaw product overview
- [SECURITY.md](SECURITY.md) — vulnerability disclosure policy
- [docs/security/pqc-whitepaper.md](docs/security/pqc-whitepaper.md) — full paper
- [docs/security/MLOCK.md](docs/security/MLOCK.md) — mlock design + verification
- [docs/security/PAPER-SUBMISSION-CHECKLIST.md](docs/security/PAPER-SUBMISSION-CHECKLIST.md) — paper-grade state
- [docs/security/constant-time-audit.md](docs/security/constant-time-audit.md) — 308-line side-channel audit
- [docs/security/verification-log-2026-08-29-30.md](docs/security/verification-log-2026-08-29-30.md) — 8/29 M6.B + 8/30 AES-GCM CT verification
- [docs/security/paper-reviewer-faq.md](docs/security/paper-reviewer-faq.md) — 12 Q&A for paper reviewers
- [CHANGELOG.md](CHANGELOG.md) — release history
- [LICENSE](LICENSE) — MIT
