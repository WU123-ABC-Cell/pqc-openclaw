# M6.B v2 N-API secure-memory addon

N-API addon for locked wrap-key memory. `secureCopy` allocates a dedicated
native mapping, locks it before copying the key, applies `MADV_DONTDUMP` where
the platform exposes it (verified on Linux), and gives Node an external Buffer.
The native finalizer scrubs, unlocks, and releases the mapping. The older
`mlock` / `munlock` exports remain for callers that need in-place swap
protection, but applying dump flags to ordinary small Node Buffers remains
unsafe because several objects may share one slab page.

## Build

Pre-requisites on the build host:

- a C++17 compiler (GCC/Clang or MSVC)
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
`src/security/native/build/Release/mlock_addon.node`. The `build/` directory is
gitignored because the binary is host-specific; rebuild after pulling.

## Runtime path selection

`src/security/mlock-helper.ts` selects the backend in priority order:

1. For `protectKey`, this addon is preferred because only its separately owned
   mapping can safely receive dump-exclusion advice.
2. For legacy in-place `mlockKey`, `process.mlock` / `process.munlock` wins when
   present, then this addon is tried.
3. Defensive no-op + single `[PQC] mlock-unavailable` warn per
   process.

Operators can inspect the chosen backend via
`mlockBackend()` (`"process" | "native" | null`) for the `[PQC]`
status log.

## File map

| File                             | Role                                                                                                                       |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `mlock-addon.cc`                 | Cross-platform lock/unlock, dedicated secure allocation, native zeroing, and finalizer cleanup                             |
| `binding.gyp`                    | `node-gyp` build config; pulls `node-addon-api` headers                                                                    |
| `mlock-addon.cjs`                | CommonJS wrapper: lazy `require()` of the binary, `isAvailable()` / `loadError()` diagnostics, throws on use without build |
| `build/Release/mlock_addon.node` | Compiled binary (gitignored)                                                                                               |

## Platform support

- **Linux x64**: secure mapping build and focused lifecycle tests passed on
  Node 22.23.1 (2026-09-09).
- **macOS / Windows / Linux arm64**: POSIX and `VirtualAlloc` / `VirtualLock`
  implementations are present, but native build and runtime validation on
  those hosts remain audit-grade backlog.
