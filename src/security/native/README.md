# M6.B v2 N-API mlock(2) native addon

Linux-first N-API addon that calls `mlock(2)` / `munlock(2)` directly
from native code. This prevents the key buffer's pages from being swapped,
but does not exclude them from core dumps. Correct `MADV_DONTDUMP` support
requires an addon-owned page mapping; applying it to ordinary small Node
Buffers is unsafe because multiple buffers can share one slab page. Used as a
fallback when `process.mlock` is missing on Node.js 24.x (verified absent on
Node 24.15.0, 2026-09-04).

## Build

Pre-requisites on the build host:

- `g++` 11+ (or any C++17 compiler)
- `python3` 3.6+ (for `node-gyp`)
- `make`
- Node.js headers (downloaded automatically by `node-gyp`)

Build the addon:

```bash
# from repo root
pnpm run build:native
# or equivalently:
npx node-gyp configure --directory=src/security/native
npx node-gyp build     --directory=src/security/native
```

The compiled binary lands at
`src/security/native/build/Release/mlock_addon.node` (Linux x64,
~86 KB, dynamically linked). The `build/` directory is gitignored
because the binary is host-specific; rebuild after pulling.

## Runtime path selection

`src/security/mlock-helper.ts` selects the backend in priority order:

1. `process.mlock` / `process.munlock` (Node 24.0.0+ stable API;
   **NOT present on 24.15.0** — verified 2026-09-04).
2. This N-API addon (when `build/Release/mlock_addon.node` exists
   and loads successfully).
3. Defensive no-op + single `[PQC] mlock-unavailable` warn per
   process.

Operators can inspect the chosen backend via
`mlockBackend()` (`"process" | "native" | null`) for the `[PQC]`
status log.

## File map

| File                             | Role                                                                                                                       |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `mlock-addon.cc`                 | C++ source: `Mlock` + `Munlock` N-API exports calling `mlock(2)` / `munlock(2)`                                            |
| `binding.gyp`                    | `node-gyp` build config; pulls `node-addon-api` headers                                                                    |
| `mlock-addon.cjs`                | CommonJS wrapper: lazy `require()` of the binary, `isAvailable()` / `loadError()` diagnostics, throws on use without build |
| `build/Release/mlock_addon.node` | Compiled binary (gitignored)                                                                                               |

## Platform support

- **Linux x64**: built and tested (Node 24.15.0, 2026-09-05).
- **macOS / Windows / Linux arm64**: not yet built. The C++ source
  is portable but the build matrix needs `binding.gyp` updates.
  Tracked in `docs/security/PAPER-SUBMISSION-CHECKLIST.md`
  P0 backlog (audit-grade cross-platform).
