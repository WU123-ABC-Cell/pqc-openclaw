# PQC OpenClaw Fork

> Experimental post-quantum work on OpenClaw. This fork is not ready for
> production keys or production data. A cryptographic helper or passing
> module test is not evidence that a product integration is complete.

[![CI: PQC](https://github.com/WU123-ABC-Cell/pqc-openclaw/actions/workflows/pqc-ci.yml/badge.svg?branch=master)](.github/workflows/pqc-ci.yml)
[![CI: side-channel](https://github.com/WU123-ABC-Cell/pqc-openclaw/actions/workflows/pqc-side-channel.yml/badge.svg?branch=master)](.github/workflows/pqc-side-channel.yml)
[![CI: deploy E2E](https://github.com/WU123-ABC-Cell/pqc-openclaw/actions/workflows/pqc-deploy-e2e.yml/badge.svg?branch=master)](.github/workflows/pqc-deploy-e2e.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

A fork of [OpenClaw](https://github.com/openclaw/openclaw), maintained independently
by [@WU123-ABC-Cell](https://github.com/WU123-ABC-Cell).

## Current capabilities and release blockers

Status is based on static review of revision
`0c273072acc724edafbf516eaa38c9dd0195d9d1`. It is not a runtime acceptance report.

The table below describes that committed baseline. Local repair candidates dated
2026-09-17 add known wrapping-key alias exclusion to both backup paths and fix
default-keyring environment/configuration reuse and silent provider downgrade.
Focused Linux checks are not release acceptance; required submission review and
cloud CI remain pending. See the [security status](docs/security/pqc-whitepaper.md)
for the changed key-selection contract and remaining blockers.

| Surface                    | Actual integration and limitations                                                                                                                                                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Device signatures          | Gateway and bundled mobile clients use ML-DSA-65 wire keys/signatures (1952/3309 bytes). Apple clients require OS 26; upgraded Ed25519 clients receive a new device ID and must pair again. No Ed25519 fallback exists.                                 |
| Identity storage           | AES-256-GCM wrapping and file/environment/OS keyring providers exist. Keypair validation, legacy migration, provider isolation and error handling remain repair targets. Encryption does not protect against a thief who also obtains the wrapping key. |
| Backups                    | Built-in state backup does not currently exclude the default wrapping-key file. The separate `scripts/backup-pqc.sh` excludes it. Treat existing archives as sensitive and retain independent recovery keys; neither policy alone makes a backup safe.  |
| Nostr                      | The production plugin still calls NIP-04. The custom `src/security/nip44-v2.ts` helper has no observed production caller and has unresolved protocol defects. Do not enable or treat it as compliant NIP-44 or delivered PQC messaging.                 |
| Key lifecycle              | Read-only `openclaw wrap-key status` is registered. Import/export/rotation remain helper APIs, not operator commands; persistent lifecycle acceptance is pending. See the diagnostic scope below.                                                       |
| Audit and required locking | Compose no longer advertises unsupported PQC logging or required-mlock switches. PQC events use the ordinary gateway log stream; there is no separate audit-file sink or fail-closed memory-locking policy.                                             |
| Secure-memory helpers      | A native secure-memory implementation and tests exist. Availability is build/platform-dependent and fallback is best-effort. This is not complete process-memory protection; immutable JS strings and runtime copies remain outside the guarantee.      |
| TLS and push               | This repository does not establish an accepted end-to-end hybrid TLS or dual-signature push deployment. Helper presence is not proof of native-client or external-service support.                                                                      |
| Test evidence              | Module tests and historical timing reports exist. Product-boundary coverage is incomplete, and random sign/verify roundtrips are not official known-answer tests. Historical results do not certify this revision.                                      |

See [the current security status and repair gates](docs/security/pqc-whitepaper.md)
before reviewing deployment or migration instructions.

### Read-only wrapping-key diagnostic (2026-10-03)

This diagnostic updates the key-lifecycle row above; the other baseline rows are
historical review notes, not a current acceptance inventory.

```sh
openclaw wrap-key status
openclaw wrap-key status --json
openclaw wrap-key status --identity-key <stored-identity-key> --json
```

The default checks only the `primary` device identity. It uses the runtime's key
selection and permission checks, then reads and validates the selected identity
from SQLite without creating a key, identity, database or migration. It does not
scan all identities. Exit code `0` means the active key and selected identity are
usable; exit code `1` means a required key/identity is missing, invalid or
unavailable. A usable legacy plaintext row is explicitly labeled `plaintext`;
`ok` is not proof of encryption, production readiness or complete key inventory.
JSON contains diagnostic metadata, not key bytes or raw provider errors.
SQLite may create or update its WAL coordination sidecars (`-wal`/`-shm`) for a
read-only connection; this is not a forensic filesystem-immutability command.
See [SQLite's read-only WAL contract](https://www.sqlite.org/wal.html#read_only_databases).
Normal configured logging may also create or append log files. PQC diagnostics
use OpenClaw's ordinary file/diagnostic transports, respecting `logging.level`
and redaction; they do not write command stdout or stderr. `logging.file` selects
the ordinary log destination, not an independent audit sink. `logging.level:
"silent"` suppresses these events.

`wrap-key import`, `export` and `rotate` are not registered. Do not use historical
command examples as recovery instructions or overwrite keys to clear an error.

## Evaluation only

Keep evaluation in a disposable environment with independent state, credentials and
ports. Do not run an unreviewed fork's scripts on a workstation carrying real secrets.
Do not install this fork over a working gateway or delete an identity/key to recover
from an error.

For a source checkout, access is subject to the repository's permissions:

```sh
git clone https://github.com/WU123-ABC-Cell/pqc-openclaw.git
cd pqc-openclaw
# Inspect README, SECURITY.md and deployment scripts before executing them.
# Use the Node version pinned by .nvmrc in an approved evaluation environment.
```

The installer, Compose recipe and older operator documents are evaluation material,
not production acceptance. Their existence does not resolve the blockers above.

## Evidence rules

- Record the exact commit, Node version, dependency lock, platform, command and exit
  code for each new result.
- Billing/usage failures that occur before testing are neither test passes nor test
  failures. The reviewed revision's supplied Actions evidence shows this kind of
  failure; this status review did not refresh remote runs.
- Local results, checked-in historical reports and current cloud CI results are
  separate evidence. A badge is a link to status, not a certification.
- Timing measurements can fail to detect a difference in one setup; they cannot
  establish a universal constant-time or zero-leakage guarantee.
- This fork does not claim FIPS 140-3 certification. Algorithm names and standards
  references are not evidence of a validated deployment.

## Repository map

| Location                            | Role                                                                    |
| ----------------------------------- | ----------------------------------------------------------------------- |
| `src/infra/device-identity*.ts`     | Device identity generation, persistence and verification                |
| `src/security/`                     | Wrapping, keyring, secure-memory and experimental cryptographic helpers |
| `src/logging/pqc-log.ts`            | PQC event logger; separate audit-file integration is not established    |
| `extensions/nostr/src/nostr-bus.ts` | Production Nostr plugin, currently NIP-04                               |
| `scripts/`                          | Operator and verification scripts; inspect scope and prerequisites      |
| `docs/security/`                    | Current status plus historical design and measurement material          |
| `docker-compose.pqc.yml`            | Evaluation deployment recipe with unresolved configuration contracts    |
| `.github/workflows/pqc-*.yml`       | Focused CI definitions; not complete product acceptance                 |

Older guides and reports remain available for traceability, but must be read subject
to the current status notice. Their command lists, counts and deployment assertions
are not automatically valid for the current checkout.

## Security disclosure

See [SECURITY.md](SECURITY.md) for private reporting channels. Its implementation
and support claims also require reconciliation; they are not evidence that a control
is implemented. Do not publish sensitive vulnerability details or real credentials
in public issues.

## License

[Apache License 2.0](LICENSE). Repository access restrictions and software licensing
are separate matters. © 2026 吴昊天 (Wu Haotian) and contributors.

## References

- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [Official NIP-44 specification](https://github.com/nostr-protocol/nips/blob/master/44.md)
