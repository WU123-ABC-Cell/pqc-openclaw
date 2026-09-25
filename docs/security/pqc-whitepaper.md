# PQC OpenClaw security status and repair gates

Author: 吴昊天 (Wu Haotian)

Status updated: 2026-09-21

Implementation baseline: `0c273072acc724edafbf516eaa38c9dd0195d9d1`

## Status and scope

This page replaces the previous delivery-oriented whitepaper as the current status
statement. It is based on static source review, not a fresh test, deployment or
cryptographic certification. The previous text remains in Git history; retained
measurement files are not deleted by this documentation change.

### Local repair candidates (2026-09-17)

The baseline table below is not a description of accepted fixes. Uncommitted local
candidates exclude known default/configured wrapping-key files and their filesystem
aliases from built-in and shell archives; old archives still require secret-bearing
handling. Independent recovery keys are required. Unknown independent key copies
and hostile same-user source-tree replacement are not covered.

The keyring candidate bounds its cache to one environment/configuration slot and
releases cached material on replacement. Explicitly injected providers remain
caller-owned; returned key buffers are borrowed and must not be held across cache
replacement/release. Partial OS configuration is rejected. Composite writes use
only the first provider, and provider errors propagate rather than silently selecting
another source. Other providers remain available for distinct historical key IDs.
This intentionally breaks automatic active-key fallback after an OS/backend failure.

For a configured OS entry, a native null read is treated as unavailable, not as
permission to fall back: the pinned adapter cannot distinguish backend errors from
absence. Unrelated OS key IDs still return null without contacting the backend.
Operators needing recovery must explicitly select the intended provider, not rely
on an outage-triggered downgrade. Native OS backend validation, complete type/proof
gates, mandatory submission review and cloud CI remain pending. No production
readiness or completed key lifecycle is claimed by these local candidates.

The 2026-09-19 identity candidate restores bounded ML-DSA public/secret pairing
checks at plaintext, wrapped-read and Doctor-salvage boundaries. A mismatched pair
is rejected before use; Doctor only rotates it through the existing explicit repair
path, whose result requires device reapproval. A wrong, missing or unavailable
wrapping key is no longer evidence that Doctor may replace the stored identity.
This proves key correspondence through the pinned library's public-key derivation;
it does not validate every redundant expanded-secret field or constitute FIPS/KAT
evidence.

Legacy Ed25519 import remains blocked. Importing a classical key into the ML-DSA-only
canonical store would leave runtime signing and gateway authentication unusable;
silently creating an ML-DSA identity under the old Ed25519 fingerprint would transfer
authorization to different key material. The operator must choose an explicit
retirement/new-identity-with-reapproval policy or approve a versioned transition
architecture before that migration path can be implemented.

The 2026-09-21 Nostr candidate replaces live NIP-04 transport with the explicitly
versioned OpenClaw PQC DM v1 profile. It uses a fresh random nonce per message,
combines the NIP-44 conversation key with an internally encapsulated ML-KEM-768
secret, authenticates the version, nonce, KEM ciphertext, message ciphertext and
both Nostr identities, and decapsulates the embedded KEM ciphertext on receive.
Live relay subscriptions accept only kind `4444`; kind `4` remains only for records
already present in the local durable queue during upgrade. Outbound sends require
an operator-pinned peer ML-KEM public key and do not downgrade automatically.
Each account publishes its ML-KEM public key as a Nostr-signed NIP-78 addressable
event. Discovery creates an untrusted candidate only: first use requires explicit
out-of-band fingerprint confirmation, and rotations require both operator approval
and a `previousFingerprint` link to the current pin.
This custom profile is not standard NIP-44 and is not interoperable with ordinary
Nostr clients. An independent cryptographic design review remains pending.

**Do not deploy this revision with production keys or production data.** Important
identity, compatibility, backup and protocol boundaries remain unresolved.
Removing an inaccurate claim does not fix its underlying implementation.

ML-DSA device authentication does not make all OpenClaw transports, clients,
plugins or external services post-quantum. Symmetric wrapping protects only when
the wrapping key and protected data are not both available to the attacker.

## Actual production paths

| Area                 | Source owner                                                                                                          | What the baseline establishes                                                                                                                                                                                       |
| -------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Gateway device proof | `src/infra/device-identity.ts`; `src/gateway/server/ws-connection/handshake-auth-helpers.ts`                          | ML-DSA-65-only proof verification, not the previously described Ed25519-first dual-signature fallback                                                                                                               |
| Native client proof  | Android `DeviceIdentityStore.kt`; shared Swift `DeviceIdentity.swift`                                                 | ML-DSA-65 wire keys/signatures. Android uses Bouncy Castle; Apple uses CryptoKit on iOS/macOS/watchOS 26 and keeps seed-backed keys in Apple-specific SQLite rows. Legacy Ed25519 authorization is not transferred. |
| Nostr messages       | `extensions/nostr/src/nostr-bus.ts`; `extensions/nostr/src/nostr-pqc-key-announcement.ts`; `src/security/nip44-v2.ts` | Production uses the custom OpenClaw PQC DM v1 profile with kind `4444`, signed untrusted key discovery, explicit peer-key pinning and no live NIP-04 fallback; old kind `4` is queue-recovery-only                  |
| Identity encryption  | `src/infra/device-identity-store.ts`; `src/security/secret-wrapping.ts`                                               | Wrapped identity storage exists, but length checks do not prove keypair correspondence and envelopes lack identity-context AAD                                                                                      |
| Key selection        | `src/security/keyring-provider.ts`                                                                                    | File, environment, OS and composite providers exist; incomplete configuration, backend failure and global-cache isolation require repair                                                                            |
| Key lifecycle        | `src/security/wrap-key-cli.ts`; `src/security/wrap-key-rotation.ts`                                                   | Auxiliary APIs exist; operator CLI registration and a verified persistent lifecycle are not established                                                                                                             |
| Logging              | `src/logging/pqc-log.ts`                                                                                              | Default PQC events can go to stdout; the logger-binding helper has no observed production caller                                                                                                                    |
| Deployment settings  | `docker-compose.pqc.yml`                                                                                              | Audit/level/require-lock variables are declared, but no corresponding production readers were found                                                                                                                 |

Native client owners:
`apps/android/app/src/main/java/ai/openclaw/app/gateway/DeviceIdentityStore.kt`
and `apps/shared/OpenClawKit/Sources/OpenClawKit/DeviceIdentity.swift`.

TLS hybrid negotiation and external push-service verification are not accepted
delivery claims in this repository. Native ML-DSA device authentication does not
establish ML-DSA push-signature validation, and an invalid classical signature
cannot safely fall back to another algorithm.

## Immediate operational limits

### Backup and recovery

The default wrapping key is stored as `wrap-key.b64` in the state directory.
The built-in backup includes state and does not exclude this file at the baseline;
the separate shell backup does exclude it. These are different policies.

Treat existing built-in archives as secret-bearing. Excluding one key file does
not protect other credentials in an archive. Keep recovery keys independently
protected and verify restoration using a disposable state copy. Do not delete,
overwrite or randomly regenerate a key used by existing ciphertext or backups.

There is no accepted `openclaw wrap-key import/export/rotate/status` CLI in this
baseline. Do not copy old whitepaper command examples as an operational procedure.
A usable restore and transactional persistent rotation flow must be implemented
and verified before claiming lifecycle support.

### Migration and compatibility

Doctor-authorized retirement validates the legacy Ed25519 public/private pair,
creates a wrapped ML-DSA-65 identity when none exists, and preserves an already-valid
ML-DSA identity. It archives the exact legacy JSON as `device.json.migrated` (or a
numbered collision-safe variant), hardens archived key material to mode `0600`, and
records both device IDs with `authorizationTransferred: false` in the migration
receipt. Existing authorization remains keyed to the retired Ed25519 device ID; it
is not copied to the ML-DSA fingerprint. A newly generated ML-DSA identity therefore
requires approval under the normal pairing policy.

Malformed or mixed Ed25519 keypairs remain active for operator review instead of
being archived. An unavailable wrapping key also aborts retirement and restores the
claimed source. This migration does not add an Ed25519 runtime fallback or establish
native-client/gateway protocol compatibility.

The outgoing gateway-call identity resolver catches load errors and returns no
identity. This may still use a valid token-authenticated route; it does not by
itself prove unauthenticated access. It does hide failures that need typed,
owner-scoped reporting rather than implicit downgrade.

### Health, audit and memory

The wrapping-key status helper can record damaged rows while setting `ok` based
only on a nonempty active key ID. Because no production monitoring integration was
established, neither a false-green deployed monitor nor complete identity health
can be inferred from this helper alone.

Do not rely on `PQC_LOG_LEVEL`, `PQC_AUDIT_LOG_PATH` or `PQC_REQUIRE_MLOCK` as
enforced controls. A configured audit-file path is not evidence that events reach
it. Default stdout output is not the promised separate audit-file integration.

Secure-memory helpers are platform/build-dependent and best-effort without a
working native path. Node version alone does not establish memory locking.
Source Buffer cleanup, native owned mappings, immutable strings and crypto-runtime
copies are different protection boundaries. No full-process memory-erasure or
universal side-channel guarantee is claimed.

## Custom Nostr protocol remains pre-release

OpenClaw PQC DM v1 now enforces a fresh 32-byte nonce, NIP-44-style padding buckets,
internal ML-KEM-768 encapsulation/decapsulation, identity-bound hybrid derivation
and complete envelope authentication. Focused tests cover roundtrip behavior,
nonce uniqueness, padding boundaries, identity substitution and mutation of the
version, nonce, KEM ciphertext, message ciphertext and MAC. Nostr transport tests
cover the real outbound envelope, missing-pin failure, kind `4444` subscription,
live kind `4` rejection and legacy durable-queue recovery. Key-management tests
cover signed NIP-78 announcements, tamper rejection, canonical latest-event
selection, first-use confirmation, compare-and-set pinning and chained rotation.

These tests establish the repository implementation contract; they are not a
third-party cryptographic review or a standards certification. The custom kind and
envelope need interoperability/versioning review before release. Nostr signatures
bind announcements to Nostr identities, while authenticated out-of-band fingerprint
confirmation remains an operator responsibility for first-use trust.

Use the [official NIP-44 specification](https://github.com/nostr-protocol/nips/blob/master/44.md)
and pinned official vectors for standards work. NIP-44 is not itself PQC and is
not a drop-in NIP-04 replacement. Any PQC extension requires its own reviewed
protocol, authenticated peer-key source, version/algorithm binding, message
freshness, complete envelope authentication and explicit downgrade policy.

## Evidence and reproducibility

The supplied review evidence for the baseline reports that PQC CI, deployment E2E
and side-channel Actions runs stopped before testing due to billing/usage limits.
This status update did not query their current remote state. They are not accepted
passing CI evidence. Cloud reruns remain pending availability.

`src/infra/mldsa65-kat.test.ts` performs random key generation, sign/verify and
rejection/property checks. Those checks are useful but are not known-answer tests:
they contain no fixed official seed/key/signature expected outputs. Add matching,
provenance-recorded official vectors before claiming KAT coverage.

The prior whitepaper referenced `pqc-fork-scripts/` runners that are absent from
the baseline's tracked files. Its counts, startup numbers and deployment results
must not be reused as reproducible results for this revision.

Retained historical material includes:

- `ct-reports/`: historical cache-timing summaries.
- `scripts/check-pqc-cache-timing-evidence.mjs`: retained-report integrity checking.
- `scripts/pqc-e2e/`: repository deployment harness definitions.
- `docs/security/verification-log-2026-08-29-30.md`: historical operator log.
- `docs/security/constant-time-audit.md`, `MLOCK.md` and paper checklists:
  earlier analysis and claims requiring reconciliation with this status.

Integrity checks do not recreate measurements. A threshold not exceeded in a
historical setup is not proof of constant time or zero leakage. Historical test
counts are not current product coverage. This fork claims neither FIPS 140-3
certification nor a validated OpenSSL deployment merely because AES-GCM is used.

For each new result, capture commit, runtime, dependency lock, platform, exact
command, exit code, logs and limitations. Keep local proof, historical reports and
cloud results distinct. Read-only source review is not runtime verification.

## Repair sequence and acceptance

| Order | Work                                 | Required evidence before declaring complete                                                                                                                |
| ----- | ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | Align claims and deployment guidance | Every delivered capability has a real production entry point and current evidence; unsupported commands/settings are not presented as operational controls |
| 2     | Backup/key-provider boundary         | Built-in and shell policies agree; keys independently protected; configured paths, restore and provider isolation/error behavior covered                   |
| 3     | Identity integrity and migration     | Mixed valid keypairs rejected; legitimate legacy migration tested; load failures visible without implicit authorization changes                            |
| 4     | Native-client/gateway handshake      | Real serialized client proofs accepted under an explicit algorithm/version policy; tamper, replay and downgrade rejected                                   |
| 5     | Persistent key lifecycle             | Registered CLI; bounded import; restart/crash-safe rotation; authenticated versioned envelope context; exceptional Buffer cleanup                          |
| 6     | Audit and lock controls              | Actual configuration readers, observable redacted sink and required-capability failure behavior verified                                                   |
| 7     | Nostr protocol and integration       | Versioned custom-profile vectors, independent hybrid design review and two-peer relay behavior on the exact release candidate                              |
| 8     | Release acceptance                   | Product-boundary regression matrix, reproducible commands and exact-SHA cloud reruns when available                                                        |

Tests must cover real handshake, production Nostr caller selection, archive
contents/recovery, CLI registration, deployment variable effects and failure paths,
not only isolated primitives. Do not skip a failing test to make CI green.

Global protocol/version and incompatible database/envelope changes need explicit
owner decisions and migration plans. USB packaging remains deferred until these
product gates are satisfied. This page is a repair status, not a completed audit.
