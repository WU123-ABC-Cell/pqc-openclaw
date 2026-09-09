# Wrap-key memory locking

> **Current status (2026-09-09)**: the Linux x64 native addon builds on Node
> 22.23.1, and its dedicated 32-byte secure-mapping path passed focused keyring
> lifecycle tests. Node 24.15.0 does not expose `process.mlock`. Backend
> selection is feature-based, not Node-version-based.

This document describes swap and core-dump protection for cached wrap keys and
its explicit limitations. `mlock(2)` alone does **not** provide core-dump
exclusion; Linux needs `MADV_DONTDUMP` on a dedicated mapping.

## 1. Threat model

The 32-byte AES-256 wrap key can remain cached in process memory. Relevant
exposure paths include:

- the kernel swapping its memory page to disk under pressure;
- a core dump after a crash;
- privileged process-memory inspection; and
- physical-memory attacks.

The native backend now allocates a dedicated mapping, locks it before copying
the decoded key, and applies `MADV_DONTDUMP` on Linux. The original Node Buffer
is scrubbed immediately after the copy. A native finalizer scrubs, unlocks, and
unmaps the allocation. This avoids applying page-wide advice to ordinary Node
slabs, where unrelated objects could share the same page.

## 2. Backend selection

`src/security/mlock-helper.ts` detects a backend once per process:

1. `protectKey()` prefers the checked-in native addon and its dedicated secure
   mapping;
2. legacy in-place locking uses a runtime `process.mlock` pair when present,
   otherwise the addon; or
3. a warned no-op when neither backend is available.

| Runtime state             | Behavior                                       |
| ------------------------- | ---------------------------------------------- |
| Built native addon        | use addon-owned locked mapping for wrap keys   |
| Runtime API only          | use in-place runtime locking without dump flag |
| Neither backend available | continue, emit one `mlock-unavailable` warning |

The helper is deliberately best-effort: locking failures do not break normal
wrap/unwrap behavior. Operators who require fail-closed locking need a separate,
reviewed deployment policy; there is no `PQC_REQUIRE_MLOCK` runtime switch.

## 3. Key lifecycle

`FileKeyring`, `EnvKeyring`, and `OsKeyring` move decoded keys into protected
native mappings when the addon is available. The source Buffer is scrubbed
immediately. Cached providers detach their reference and zero the external
Buffer on release; the native finalizer repeats the scrub before unmapping.
`CompositeKeyring.release()` releases each inner provider on a best-effort
basis, and the default keyring is also released by the process exit hook.

Lifecycle ownership performs one release for each cached Buffer. Do not rely on
per-caller kernel reference counting for repeated or overlapping locks,
especially with slab-backed Node Buffers.

## 4. Audit events

| Event               | Meaning                                                         |
| ------------------- | --------------------------------------------------------------- |
| `mlock`             | a locking backend reported success (debug)                      |
| `munlock`           | the release path attempted an unlock (debug)                    |
| `mlock-unavailable` | neither backend could provide locking (warned once per process) |

`backend=native-secure-mapping` means a dedicated mapping was locked and, on
Linux, accepted `MADV_DONTDUMP`. A plain `backend=native` or `backend=process`
event proves only in-place swap locking.

## 5. Verification

From the repository root on Linux:

```bash
pnpm build:native
node - <<'NODE'
const addon = require("./src/security/native/mlock-addon.cjs");
const source = Buffer.alloc(32, 0x41);
if (!addon.isAvailable()) throw new Error("native mlock addon unavailable");
const key = addon.secureCopySync(source);
addon.secureZeroSync(source);
if (!key.equals(Buffer.alloc(32, 0x41))) throw new Error("copy mismatch");
addon.secureZeroSync(key);
if (!key.equals(Buffer.alloc(32))) throw new Error("scrub mismatch");
console.log("native 32-byte secure mapping roundtrip: OK");
NODE

node scripts/run-vitest.mjs run src/security/mlock-helper.test.ts
```

The 2026-09-09 local gate passed all 20 focused mlock-helper tests, 86 focused
key lifecycle tests, and the native build on Linux x64 / Node 22.23.1. These
local results do not imply that hosted GitHub Actions ran successfully.

The healthcheck probes the runtime API first and the native addon second:

```bash
/usr/local/bin/healthcheck-pqc.sh --skip-keyring
```

Use `--skip-keyring` for the installer's default file-backed deployment. If an
operator explicitly migrated to an OS keyring, pass the exact configured
service and account values instead.

## 6. Deployment requirements and limitations

- Deployments need the native addon built with `pnpm build:native`.
- Lock limits and host policy can still make `mlock(2)` / `VirtualLock` fail.
- Node 24.15.0 has no `process.mlock`; upgrading Node alone does not activate
  locking.
- macOS, Windows, and Linux arm64 build/runtime validation remain backlog.
- Linux core-dump exclusion is enabled only for addon-owned mappings; fallback
  buffers and platforms without an equivalent dump-exclusion flag retain the
  documented limitation.
- File, environment, and OS-keyring adapters must first materialize base64url
  key text as immutable JavaScript strings. Those encoded copies, plus any
  internal copy held by the crypto runtime, cannot be reliably scrubbed by this
  addon; the guarantee covers the decoded working Buffer owned by the built-in
  providers.
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
