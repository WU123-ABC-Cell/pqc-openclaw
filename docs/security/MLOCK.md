# Wrap-key memory locking

> **Current status (2026-09-07, `d3b940a21e`)**: the Linux native addon
> builds and completed a real 32-byte `mlock`/`munlock` roundtrip on Node
> 24.15.0. Node 24.15.0 does not expose `process.mlock`. Backend selection is
> feature-based, not Node-version-based.

This document describes swap protection for cached wrap keys and its explicit
limitations. `mlock(2)` does **not** provide core-dump exclusion.

## 1. Threat model

The 32-byte AES-256 wrap key can remain cached in process memory. Relevant
exposure paths include:

- the kernel swapping its memory page to disk under pressure;
- a core dump after a crash;
- privileged process-memory inspection; and
- physical-memory attacks.

The current Linux native backend calls `mlock(2)` to reduce swap exposure and
`munlock(2)` when a cached key is released. It does not set `VM_DONTDUMP`, so it
does not claim to protect against core dumps. Safe `MADV_DONTDUMP` support needs
an addon-owned, page-aligned mapping; applying it to an ordinary Node Buffer
could affect unrelated objects sharing the same slab page.

## 2. Backend selection

`src/security/mlock-helper.ts` detects a backend once per process:

1. a future runtime-provided `process.mlock` / `process.munlock` pair;
2. the checked-in Linux native addon at
   `src/security/native/mlock-addon.cjs`; or
3. a warned no-op when neither backend is available.

| Runtime state             | Behavior                                       |
| ------------------------- | ---------------------------------------------- |
| Runtime API available     | use the runtime API                            |
| Built Linux addon         | use native `mlock(2)` / `munlock(2)`           |
| Neither backend available | continue, emit one `mlock-unavailable` warning |

The helper is deliberately best-effort: locking failures do not break normal
wrap/unwrap behavior. Operators who require fail-closed locking need a separate,
reviewed deployment policy; there is no `PQC_REQUIRE_MLOCK` runtime switch.

## 3. Key lifecycle

`FileKeyring` and `OsKeyring` lock a decoded key after caching it. Their release
paths first detach the cached reference, zero the Buffer with `fill(0)`, then
attempt `munlock`. `CompositeKeyring.release()` releases each inner provider on
a best-effort basis, and the default keyring is also released by the process
exit hook.

Lifecycle ownership performs one release for each cached Buffer. Do not rely on
per-caller kernel reference counting for repeated or overlapping locks,
especially with slab-backed Node Buffers.

## 4. Audit events

| Event               | Meaning                                                         |
| ------------------- | --------------------------------------------------------------- |
| `mlock`             | a locking backend reported success (debug)                      |
| `munlock`           | the release path attempted an unlock (debug)                    |
| `mlock-unavailable` | neither backend could provide locking (warned once per process) |

An `mlock` success means swap locking succeeded for the supplied range. It is
not evidence of core-dump exclusion.

## 5. Verification

From the repository root on Linux:

```bash
pnpm build:native
node - <<'NODE'
const addon = require("./src/security/native/mlock-addon.cjs");
const key = Buffer.alloc(32, 0x41);
if (!addon.isAvailable()) throw new Error("native mlock addon unavailable");
addon.mlock(key);
key.fill(0);
addon.munlock(key);
console.log("native 32-byte mlock/munlock roundtrip: OK");
NODE

node scripts/run-vitest.mjs run src/security/mlock-helper.test.ts
```

The 2026-09-07 local gate passed all 18 focused mlock-helper tests and the
native 32-byte roundtrip. The wider focused PQC gate passed 275 tests. These
local results do not imply that hosted GitHub Actions ran successfully.

The healthcheck probes the runtime API first and the native addon second:

```bash
/usr/local/bin/healthcheck-pqc.sh --skip-keyring
```

Use `--skip-keyring` for the installer's default file-backed deployment. If an
operator explicitly migrated to an OS keyring, pass the exact configured
service and account values instead.

## 6. Deployment requirements and limitations

- Linux builds need the native addon built with `pnpm build:native`.
- `RLIMIT_MEMLOCK` and host policy can still make `mlock(2)` fail.
- Node 24.15.0 has no `process.mlock`; upgrading Node alone does not activate
  locking.
- macOS, Windows, and Linux arm64 backend/build validation remain backlog.
- addon-owned secure allocation plus core-dump exclusion remains backlog.
- root or same-user process-memory access, cold-boot attacks, EM/power analysis,
  and fault injection are outside this control's guarantee.

## 7. Evidence interpretation

Memory locking is independent of the checked-in timing reports. The reports in
`docs/security/ct-reports/` are retained historical measurements and are
validated for integrity by:

```bash
node scripts/check-pqc-cache-timing-evidence.mjs
```

They record that no statistically significant difference exceeded the chosen
threshold under the documented setup. They are not fresh benchmarks of the
current checkout and are not proof of constant-time behavior.
