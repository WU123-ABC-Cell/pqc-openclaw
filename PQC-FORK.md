# PQC fork: scope, deployment, and limitations

This private fork adds post-quantum identity and key-exchange paths, hardened
wrap-key handling, repository-owned deployment tooling, and retained
side-channel evidence to OpenClaw. It is maintained independently from
`openclaw/openclaw`.

## Current snapshot

The 2026-09-10 baseline passed locally on Linux x64 / Node 24.16.0:

- `pnpm tsgo:core`;
- 277 focused Vitest tests across the PQC, state, and secure-memory paths;
- a native secure-mapping kernel probe showing locked, non-dumpable memory and
  finalizer cleanup;
- five deploy harnesses under `scripts/pqc-e2e/`;
- a complete isolated installer/build/artifact check; and
- integrity validation of all 14 checked-in cache-timing reports.

Three self-contained workflows are checked in under `.github/workflows/`.
Hosted GitHub Actions is not currently green: the private repository's runs
fail before runner allocation, with no job steps or logs. Local verification is
not a substitute for a successful hosted run.

## What the fork implements

| Area                    | Fork behavior                                                        |
| ----------------------- | -------------------------------------------------------------------- |
| Signatures              | ML-DSA-44/65/87 support; ML-DSA-65 is the primary PQC profile        |
| Key encapsulation       | ML-KEM-512/768/1024 support; ML-KEM-768 is the primary profile       |
| Secret wrapping         | AES-256-GCM                                                          |
| Device identity storage | additive SQLite migration with nullable PQC columns                  |
| Wrap-key providers      | file, environment, OS-keyring, and composite provider APIs           |
| RAM swap protection     | feature-detected runtime hook or checked-in Linux native addon       |
| Deployment tooling      | installer, healthcheck, backup, Prometheus collector, five harnesses |

Classic algorithms remain where compatibility requires them. Do not describe
the fork as having replaced every Ed25519/x25519/AES-128 use without a fresh,
whole-repository call-path audit.

## Wrap-key provisioning

The production installer creates a 32-byte base64url key at
`$STATE_DIR/wrap-key.b64`, sets mode 0600, and points the generated systemd unit
at it through `OPENCLAW_WRAP_KEY_FILE`. It also creates
`$STATE_DIR/openclaw.env` containing the gateway token.

The installer does not populate an OS keyring. `OsKeyring` and
`CompositeKeyring` exist in the runtime, but migration to a platform keyring is
an explicit operator procedure because it may need an interactive unlock. There
is no checked-in one-command migration wrapper in the current tree.

Never replace or delete a wrap key while ciphertext still depends on it.
Current operator docs treat key rotation as unsupported until a reviewed,
transactional rewrap procedure is available.

## Memory locking

`src/security/mlock-helper.ts` chooses the first available backend:

1. a future `process.mlock` / `process.munlock` pair;
2. `src/security/native/mlock-addon.cjs` on a supported Linux build; or
3. a warned no-op.

Node 24.15.0 does not expose `process.mlock`. On Linux, build the addon
explicitly:

```bash
pnpm build:native
node scripts/run-vitest.mjs run src/security/mlock-helper.test.ts
```

`mlock(2)` protects against swap only. It does not exclude pages from core
dumps. Core-dump protection needs addon-owned, page-aligned secure allocation;
applying `MADV_DONTDUMP` to ordinary Node Buffers could affect unrelated slab
contents. See `docs/security/MLOCK.md`.

## Production install

Run from a Git checkout. The install root must be outside that checkout because
the installer copies the exact committed tree with `git archive HEAD`:

```bash
git clone https://github.com/WU123-ABC-Cell/pqc-openclaw.git /srv/pqc-openclaw-source
cd /srv/pqc-openclaw-source
sudo bash scripts/install-pqc.sh \
  --install-root /opt/pqc-openclaw \
  --state-dir /var/lib/pqc-openclaw \
  --service-user pqc-openclaw \
  --node-version 24.16.0

sudo systemctl daemon-reload
sudo systemctl enable --now pqc-openclaw
/usr/local/bin/healthcheck-pqc.sh --skip-keyring
```

The installer:

- enforces the requested Node version and the exact `packageManager` pnpm pin;
- installs the complete committed workspace and builds `dist/`;
- writes the file-backed wrap key and gateway-token environment file;
- installs the healthcheck, backup, and textfile-collector wrappers; and
- renders Linux gateway and daily-backup systemd units.

It does not start or enable those units, populate an OS keyring, or install a
macOS launchd service.

For isolated Linux validation, `--sandbox-root PATH` requires an existing,
empty, non-symlink directory owned by the caller with mode 0700. Sandbox mode
does not modify host users, services, `/etc`, or `/usr/local`.

## Verification commands

```bash
pnpm tsgo:core
node scripts/check-pqc-cache-timing-evidence.mjs
node scripts/run-vitest.mjs run src/security/mlock-helper.test.ts
```

The exact focused CI file list is defined in `.github/workflows/pqc-ci.yml`.
Deployment harnesses are under `scripts/pqc-e2e/`; the full sandbox install is
defined by `.github/workflows/pqc-deploy-e2e.yml`.

The 14 reports in `docs/security/ct-reports/` are historical measurements. The
integrity checker confirms their schema, coverage, and threshold claims; it does
not rerun the benchmark. Their recorded maximum `|t|` is 1.983 under threshold
4.5. This supports the limited statement that no statistically significant
difference exceeded that threshold in the recorded environment. It is not proof
of constant-time behavior.

## Explicit limitations

- The repository is private and independently maintained.
- Hosted CI has not completed while the private-repository runner is unassigned.
- The project has no independent third-party cryptographic audit.
- It is not FIPS 140-3 certified, and JavaScript PQC operations are not provided
  by an OpenSSL FIPS module.
- Timing evidence is fixed, environment-specific, and not a fresh benchmark of
  every current commit.
- Per-operation cache testing, active PRIME+PROBE/FLUSH+RELOAD, hardware
  counters, EM/power analysis, and fault injection remain untested.
- `mlock` does not provide core-dump exclusion.
- Secure-memory backend/build validation for Linux arm64, macOS, and Windows is
  backlog.
- The installer is Linux-systemd-oriented; macOS service management is manual.
- Backup and Prometheus schedules are operator-managed.
- Current backup database-schema verification recognizes the legacy `state.db`
  layout; separately run SQLite integrity checks for
  `$STATE_DIR/state/openclaw.sqlite` before relying on a restore point.

## Documentation map

- `README.md` — overview and quick start
- `docs/USER_GUIDE.md` — first install and normal use
- `docs/security/OPERATIONS.md` — on-call and recovery runbook
- `docs/security/MIGRATION.md` — upstream-to-fork migration
- `docs/security/MLOCK.md` — memory-lock design and limits
- `docs/security/constant-time-audit.md` — self-audit
- `docs/security/PAPER-SUBMISSION-CHECKLIST.md` — evidence and claim boundaries
- `SECURITY.md` — vulnerability reporting
