# Changelog

All notable changes to the PQC OpenClaw fork are documented in this
file. Dates are in `YYYY-MM-DD` format. The format is loosely based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project follows [Semantic Versioning](https://semver.org/).

## [Unreleased] — paper-grade and production-grade hardening

### Added
- **Post-quantum cryptography** (FIPS 203/204):
  - **ML-KEM-768** (FIPS 203) key encapsulation for Nostr DM NIP-44 v2
    envelope and Gateway TLS hybrid handshake
  - **ML-DSA-65** (FIPS 204) device-identity signing, replacing
    Ed25519 as the primary signature (Ed25519 retained as
    dual-signature fallback for backward compatibility)
- **AES-256-GCM wrap envelope** for at-rest protection of the
  ML-DSA-65 private key in `state.db`
- **OS keyring integration** via `@napi-rs/keyring` 1.3.0
  (macOS Keychain, Windows Credential Manager, Linux Secret
  Service via libsecret + gnome-keyring / KWallet / KeePassXC)
- **`src/security/mlock-helper.ts`**: defensive `mlock(2)` wrapper
  for the wrap key, pinning it in physical RAM and excluding it
  from core dumps. **Production-hardened** with `MAX_MLOCK_BYTES`
  1 MiB DoS guard, platform/arch/node context in failure log,
  debug-level success log, defensive type check. 13/13 vitest.
- **Side-channel validation** across 28 operations × 129,200 ops:
  - 14 user-space timing tests (`dudect`-style, `sidechannel-*.mjs`)
  - 14 cache-timing tests (valgrind callgrind, `cache-timing-ct*.mjs`)
  - 4 evidence layers (user-space timing, cache hierarchy,
    FIPS 203/204 KAT, side-channel test isolation)
  - 9 paper supplementary docs (main paper, verification log,
    reviewer FAQ, submission checklist, MLOCK, constant-time
    audit, 14 reports, 3 user-space scripts, 5 cache-timing
    scripts, 1 regression guard)
- **`docs/security/MLOCK.md`** (10 K): mlock design + verification
  + Node 24.15+ deployment guide
- **`docs/security/verification-log-2026-08-29-30.md`** (300 lines):
  8/29 M6.B OsKeyring real deployment + 8/30 AES-GCM
  cache-timing completion verification
- **`docs/security/paper-reviewer-faq.md`** (124 lines): 12 Q&A
  for paper reviewers
- **`docs/security/PAPER-SUBMISSION-CHECKLIST.md`** (60 lines):
  paper-grade state + audit-grade backlog
- **`docs/security/constant-time-audit.md`** (308 lines, side doc):
  side-channel attack surface analysis
- **`SECURITY.md`**: PQC-fork-specific vulnerability disclosure
  policy (replaces upstream's generic policy with PQC-fork
  reporting channel)
- **`PQC-FORK.md`**: 13.5 K production user-facing doc covering
  TL;DR, what's different from upstream, who should use it,
  production deployment (6-step guide), side-channel validation
  scope, cryptographer audit path, limitations, and project
  status
- **`pqc-fork-scripts/check-cache-timing-claims.sh`** (regression
  guard): 14 reports must show no leak, exit 1 on regression
- **`pqc-fork-scripts/verify-mlock-standalone.mjs`**: standalone
  logic test for the mlock helper, runnable on Node 22 even when
  vitest is not installed

### Changed
- **`FileKeyring`** in `src/security/keyring-provider.ts`: now
  caches the decoded key in `cachedKey` and calls
  `mlockKey(cachedKey, "file:...")` after first read; `invalidate()`
  calls `munlockKey` before clearing the cache
- **`OsKeyring`** in `src/security/os-keyring.ts`: now caches the
  decoded key in `cachedKey` and calls `mlockKey` on first
  read; `getKeyById()` follows the same mlock-once pattern
- **`CompositeKeyring`** in `src/security/keyring-provider.ts`:
  new `release()` method walks inner providers
- **Module-level shutdown hook** in
  `src/security/keyring-provider.ts`:
  `process.on("exit", releaseDefaultKeyring)` to munlock wrap
  keys on clean exit (best-effort)
- **`package.json` `engines.node`**: now accepts `>=24.15.0 <25`
  in addition to `>=22.22.3 <23` and `>=25.9.0`
- **Whitepaper** (`docs/security/pqc-whitepaper.md`): 8/30
  cumulative claim upgrade from 12 ops × 9.6K → 14 ops × 11.2K
  cache-timing (AES-GCM added); cumulative paper claim
  7 hot paths × 28 ops × 129.2K ops × 0 leak
- **`@noble/post-quantum`**: 0.7.0 (FIPS 203/204 reference impl)
- **`@napi-rs/keyring`**: 1.3.0 (OS keyring dynamic loader)

### Fixed
- **Pre-existing `pnpm-lock.yaml` drift from 2026-08-25**: the
  8/25 M6.B commit added `@noble/post-quantum@0.7.0` and
  `@napi-rs/keyring@1.3.0` to `package.json` but did not regenerate
  the lockfile. `pnpm install --no-frozen-lockfile` (2026-09-01)
  regenerated the lockfile, restoring `pnpm install --frozen-lockfile`
  compatibility and unblocking vitest in CI.

### Security
- **mlock(2) integration** (defense-in-depth, Node 24.15+): wrap
  key 32 bytes pinned in physical RAM, excluded from core dumps.
  Defensive no-op on Node 22.23.1 (current default) with a single
  `[PQC] mlock-unavailable` warn per process. See MLOCK.md for
  the full design.

## [Pre-1.0] — 14/14 milestones (M1-M14) + 8/25 paper pre-grade

This is the upstream + initial PQC fork work, before the
8/30 paper-grade evidence upgrade. Tracked separately in
git history:

- M1-M12: device-identity ML-DSA-65, keyring providers, wrap-key
  rotation, m12-v3 FileKeyring auto-inject (`f89f296687`)
- M13: pnpm build + doctor + fork boot + full validation
- M14: `WU123-ABC-Cell/pqc-openclaw:master` initial push
- 8/25: M6.B OsKeyring real deployment (`21bc128b6b`)
- 8/25-8/27: side-channel dudect-style tests (AES-GCM,
  ML-DSA, ML-KEM, 14 ops × 118K)
- 8/27-8/28: valgrind callgrind cache-timing (12 ML algos ×
  9.6K ops)

See `git log` for the full pre-1.0 history.

## Unreleased Backlog

The following are tracked but not yet implemented. They are
**not blockers** for the current paper-grade state. They are
required to reach **audit-grade** (third-party cryptographer
sign-off) and to push the fork from "self-attested" to
"externally validated".

### P0 (paper accept / commercial deploy)
- [ ] **Third-party cryptographer audit** (4-6 weeks + 50-150K
  USD). See `docs/security/paper-reviewer-faq.md` Q6.
- [ ] **Node 24.15+ production deployment with full regression**
  (4-5 hours autonomous). The `package.json` `engines.node`
  allows it; the operator must install Node 24.15+ on the
  production host and re-run the 28 ops side-channel regression
  to verify the mlock active path. Currently verified only on
  Node 22.23.1 (defensive no-op path).
- [ ] **FIPS 140-3 certification** (1-2 years + 100K-1M USD).
  Required for regulated-industry deployment. The fork's
  AES-256-GCM wrap already relies on OpenSSL 3.x FIPS 140-3
  validated path, which simplifies the certification (the
  cryptographic module is already certified, the fork code is
  the integrator).

### P1 (paper-grade rigor)
- [ ] **Per-operation cache-timing** (per-op dump+zero via
  SIGUSR1/SIGUSR2, 14 algo × 5000 ops × 2 class = 98h of CPU).
  The current implementation uses per-process aggregate
  (K=20 process/class × N=20 ops). Per-op testing would tighten
  the side-channel claim but is not required for paper
  acceptance.
- [ ] **Hardware-level cache-timing validation** (FLUSH+RELOAD,
  PRIME+PROBE) on Intel i7-14650HX + AMD Zen 4 + Apple M1+
  platforms. Requires Intel/AMD perf counter tooling and
  ~1 day per platform.
- [ ] **EM / power / fault injection** (requires professional
  hardware, e.g. ChipWhisperer). Out of scope of the fork
  code; this is a hardware test.
- [ ] **AES-NI hardware timing** (Intel perf counter trace of
  AES-256-GCM encrypt/decrypt, ~1 day). The fork relies on
  OpenSSL 3.x which is documented constant-time, but the
  hardware-level claim has not been independently verified.

### P2 (future product evolution)
- [ ] **HSM integration** (YubiKey / TPM 2.0 for wrap-key
  storage). Replaces the OS keyring as the master key store.
  Useful for hardware-rooted trust.
- [ ] **FIPS 205 SLH-DSA** (Stateless Hash-Based Signature)
  support. Drop-in addition to ML-DSA-65 for the
  longest-retention use cases.
- [ ] **FIPS 206 FN-DSA** (Falcon) support. Smaller signatures
  than ML-DSA-65, alternative for bandwidth-constrained paths.
- [ ] **BoringSSL TLS 1.3 hybrid** (X25519+ML-KEM-768) for the
  Gateway TLS handshake. Currently relies on Node 22's built-in
  OpenSSL TLS stack, which does not yet ship X25519MLKEM768.

## Contributing

Contributions are MIT-licensed. See [SECURITY.md](SECURITY.md) for
vulnerability disclosure and [PQC-FORK.md](PQC-FORK.md) for the
fork's contribution model. New algorithms or test cases should
follow the pattern in
`src/security/mlock-helper.test.ts` and
`pqc-fork-scripts/cache-timing-ct.mjs`.
