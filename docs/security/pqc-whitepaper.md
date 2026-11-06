# PQC OpenClaw security status and repair gates

Author: 吴昊天 (Wu Haotian)

Status updated: 2026-11-03

Implementation checked: local `r3-fixes-20261103` at
`c04df90d4647a0112149ddf63d51da0470a97cf6`. Public `master` at the start
of this review was `4e14148`. The local branch is not production accepted.

## Status and scope

This page separates the checked code from the dated review retained below.
The local branch has focused test evidence, but no real Compose container
acceptance, lost-key recovery exercise on an installed system, or native Apple
acceptance. It is not a cryptographic certification or production release.

| Area                       | Checked implementation and remaining boundary                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Device identity            | Gateway and bundled clients use ML-DSA-65 proofs. Wrapped SQLite rows authenticate row context and reject mismatched keypairs. Legacy Ed25519 authorization is not transferred; Apple OS 26 native acceptance remains pending.                                                                                                                                                                                                                                                |
| Backups                    | Both `openclaw backup create` and `scripts/backup-pqc.sh` exclude known default/configured wrapping-key files, their resolved targets and hardlink aliases. Encrypted identity rows remain in the archive, so recovery requires the original key stored separately. Other secrets in the archive are not encrypted by this exclusion; independent key copies at unknown paths cannot be identified. Older archives may contain keys and must remain protected as credentials. |
| Recovery                   | The branch prevents a missing default wrapping-key file from being replaced when wrapped identities exist or state cannot be inspected. The installer uses exclusive key creation. Real installed-system recovery remains to be exercised.                                                                                                                                                                                                                                    |
| Retention                  | The branch selects one local archive for each of seven newest UTC backup dates and four older ISO weeks. Sparse histories can have fewer points; off-host retention is separate. A real multiweek restore exercise remains pending.                                                                                                                                                                                                                                           |
| Nostr                      | Production uses the custom OpenClaw PQC DM v1 kind `4444` transport. It is not standard NIP-44 or interoperable with ordinary Nostr clients; independent protocol review remains pending.                                                                                                                                                                                                                                                                                     |
| Deployment                 | Compose file-token wiring has a local candidate. Container UID 1000 secret reads, real startup and Gateway/CLI authentication have not been exercised here. No separate PQC audit-file sink or required memory-locking policy is claimed.                                                                                                                                                                                                                                     |
| Key lifecycle and evidence | `openclaw wrap-key status` is read-only. Import/export/rotate are not operator commands. A separate SQLite v7 rotation candidate needs native Apple verification. Focused tests and historical timing files do not establish release acceptance or official known-answer tests.                                                                                                                                                                                               |

For current backup behavior and restore requirements, see
[the backup command guide](../cli/backup.md) and
[operations guide](OPERATIONS.md). For historical evidence, use the exact
commit and run identifier cited with each result.

<details>
<summary>Historical review notes (0c273 baseline and September–October 2026 notes; not current operating guidance)</summary>

The sections below document earlier findings and proposed repairs. Their
descriptions of “current” behavior apply only to their stated dates and do not
supersede the status table above.

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

## Historical production paths at the reviewed baseline

| Area                 | Source owner                                                                                                          | What the baseline establishes                                                                                                                                                                                       |
| -------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Gateway device proof | `src/infra/device-identity.ts`; `src/gateway/server/ws-connection/handshake-auth-helpers.ts`                          | ML-DSA-65-only proof verification, not the previously described Ed25519-first dual-signature fallback                                                                                                               |
| Native client proof  | Android `DeviceIdentityStore.kt`; shared Swift `DeviceIdentity.swift`                                                 | ML-DSA-65 wire keys/signatures. Android uses Bouncy Castle; Apple uses CryptoKit on iOS/macOS/watchOS 26 and keeps seed-backed keys in Apple-specific SQLite rows. Legacy Ed25519 authorization is not transferred. |
| Nostr messages       | `extensions/nostr/src/nostr-bus.ts`; `extensions/nostr/src/nostr-pqc-key-announcement.ts`; `src/security/nip44-v2.ts` | Production uses the custom OpenClaw PQC DM v1 profile with kind `4444`, signed untrusted key discovery, explicit peer-key pinning and no live NIP-04 fallback; old kind `4` is queue-recovery-only                  |
| Identity encryption  | `src/infra/device-identity-store.ts`; `src/security/secret-wrapping.ts`                                               | Wrapped identity storage exists, but length checks do not prove keypair correspondence and envelopes lack identity-context AAD                                                                                      |
| Key selection        | `src/security/keyring-provider.ts`                                                                                    | File, environment, OS and composite providers exist; incomplete configuration, backend failure and global-cache isolation require repair                                                                            |
| Key lifecycle        | `src/security/wrap-key-cli.ts`; `src/security/wrap-key-rotation.ts`                                                   | Auxiliary APIs exist; operator CLI registration and a verified persistent lifecycle are not established                                                                                                             |
| Logging              | `src/logging/pqc-log.ts`                                                                                              | PQC events use the canonical file/diagnostic transports with ordinary level filtering and redaction, not command stdout/stderr; there is no independent audit sink                                                  |
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

At the `0c273` historical baseline, the default wrapping key was stored as
`wrap-key.b64` in the state directory and the built-in backup did not exclude
it. That warning does not describe the checked implementation above.

Treat existing built-in archives as secret-bearing. Excluding one key file does
not protect other credentials in an archive. Keep recovery keys independently
protected and verify restoration using a disposable state copy. Do not delete,
overwrite or randomly regenerate a key used by existing ciphertext or backups.

The 2026-10-03 diagnostic adds `openclaw wrap-key status [--json]` and
`--identity-key <key>` (default: `primary`). It checks only that selected identity,
using the runtime's key-selection and permission policy and a read-only SQLite
read. It does not create missing state, repair, migrate, or scan all identities.
Exit `0` means the active key and checked identity are usable; exit `1` means
missing, invalid or unavailable state. JSON exposes metadata only, not key bytes
or raw provider/store errors. A `plaintext` row may be usable but is not encrypted.
Read-only means no identity/key/schema writes, not filesystem immutability:
[SQLite WAL readers](https://www.sqlite.org/wal.html#read_only_databases) may
create or update `-wal`/`-shm` coordination sidecars. Do not use this command for
forensic preservation or delete a live database's sidecars to prepare a query.
Normal configured logging may create or append log files; identity/key/schema
read-only guarantees do not imply a write-free logging transport.

`openclaw wrap-key import`, `export` and `rotate` are still unregistered. Do not
copy old whitepaper command examples as an operational procedure. A usable restore
and transactional persistent rotation flow, bounded imports and failure cleanup
must be implemented and verified before claiming lifecycle support.

### Migration and compatibility

New device-identity envelopes use AES-GCM associated data to bind the SQLite
identity key, device ID, canonical ML-DSA public key, envelope version and
wrapping-key ID. Runtime reads reject old unbound envelopes. With the original
wrapping key available, `openclaw doctor --fix` verifies each old wrapped row's
public/private pair and upgrades it, including custom identity keys. Successful
upgrades preserve signing keys and device IDs and are idempotent. Review Doctor's
changes and warnings, then verify each required identity with
`openclaw wrap-key status --identity-key <stored-identity-key> --json`.

Failed upgrades preserve their rows; other valid rows may already have upgraded.
Bound-envelope authentication failures preserve the identity and require recovery
from the original key or a trusted backup. Migration cannot prove historical
row ownership for old unbound data. AAD does not prevent database rollback or
cross-database replay with the same identity key and wrapping key.

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

The status helper now requires a valid active key and valid requested identity
rows before reporting `ok`. The operator CLI always requests one identity and
reports failures nonzero; calling the helper without identity keys still checks
the provider only. Neither entry point is an all-identities scan or an accepted
production-monitoring integration. Successful availability does not imply that a
legacy plaintext row is encrypted.

The evaluation Compose recipe no longer sets `PQC_LOG_LEVEL`,
`PQC_AUDIT_LOG_PATH` or `PQC_REQUIRE_MLOCK`: the gateway does not implement
those switches. PQC events use OpenClaw's ordinary file/diagnostic transports,
not command stdout/stderr or a separate audit-file sink. They honor
`logging.level` (including `silent`), `logging.file` and canonical redaction.
Memory locking remains best-effort rather than fail-closed.

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

`src/infra/mldsa65-properties.test.ts` performs random key generation,
sign/verify and rejection/property checks. These are not known-answer tests.
`src/infra/mldsa65-acvp.test.ts` compares full fixed outputs from the
[NIST ACVP-Server v1.1.0.43 samples](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files):
ML-DSA-65 KeyGen group 2/case 26 and deterministic internal SigGen group
10/case 147. This covers two dependency-level operations; the SigGen sample's
raw message is not valid UTF-8 and does not exercise the product's string
payload wrapper. `src/infra/mldsa44-87-acvp.test.ts` adds fixed KeyGen and
deterministic internal SigGen answers for ML-DSA-44 (1/1, 8/110) and
ML-DSA-87 (3/51, 12/172). Those two parameter sets are dependency-level
checks; the device-proof protocol currently uses ML-DSA-65.
`src/security/ml-kem-768-acvp.test.ts` separately compares
complete ML-KEM-768 KeyGen, encapsulation and decapsulation outputs against
the same pinned NIST sample set (groups/cases 2/26, 2/26 and 5/86). These
tests exercise the dependency's deterministic interfaces and the product's
public-key derivation wrapper. `src/security/ml-kem-512-1024-acvp.test.ts`
adds the same three dependency-level operations for ML-KEM-512 (1/1, 1/1,
4/76) and ML-KEM-1024 (3/51, 3/51, 6/96). These checks do not establish
Nostr envelope security, FIPS certification or full algorithm validation.

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

</details>
