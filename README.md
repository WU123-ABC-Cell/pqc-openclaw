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

Updated 2026-11-03. This table describes the code in the commit containing this
file. It supersedes the historical `0c273072acc724edafbf516eaa38c9dd0195d9d1`
review. The third-review repairs on `r3-fixes-20261103` remain candidates until
their own deployment and recovery checks pass; the public `master` baseline at
the start of this work was `4e14148`. See the [security status](docs/security/pqc-whitepaper.md)
for exact limits and historical scope.

| Surface           | Current implementation and remaining limit                                                                                                                                                                                                                                                                                                     |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Device signatures | Gateway and bundled mobile clients use ML-DSA-65 wire proofs. Apple clients require OS 26; native Apple acceptance remains pending. Legacy Ed25519 authorization is not transferred.                                                                                                                                                           |
| Identity storage  | AES-256-GCM identity wrapping binds row context and checks keypair correspondence. A missing file key no longer triggers replacement when wrapped rows exist. Keep the original wrapping key separately; losing it makes encrypted identities unrecoverable.                                                                                   |
| Backups           | Both `openclaw backup create` and `scripts/backup-pqc.sh` exclude the known default/configured wrapping-key files, targets and hardlink aliases. They do not exclude unknown independent copies or encrypt other archive contents. Older archives may contain keys. Local daily/weekly rotation is a candidate pending real recovery exercise. |
| Nostr             | The production plugin uses the custom OpenClaw PQC DM v1 kind `4444` transport and signed key announcements. This is not standard NIP-44 or interoperable with ordinary Nostr clients; independent protocol review remains pending.                                                                                                            |
| Key lifecycle     | Read-only `openclaw wrap-key status` is registered. Import/export/rotation are not operator commands. A separate SQLite v7 rotation candidate still needs native Apple acceptance.                                                                                                                                                             |
| Deployment        | The Compose file-token path and secret handling have a local repair candidate. Real container startup, non-root secret access and gateway/CLI authentication remain to be exercised.                                                                                                                                                           |
| Audit and memory  | PQC events use ordinary logging. There is no separate audit-file sink or fail-closed memory-locking policy. Secure-memory coverage depends on platform and build.                                                                                                                                                                              |
| TLS and push      | This repository has no accepted end-to-end hybrid TLS deployment or deployed external-service PQC push-signature integration. Helper code does not establish client or service support.                                                                                                                                                        |
| Evidence          | Focused tests and historical timing reports are not production acceptance, cryptographic certification or official known-answer tests. Check CI against the exact commit being deployed.                                                                                                                                                       |

See [the current security status and repair gates](docs/security/pqc-whitepaper.md)
before reviewing deployment or migration instructions.

### Read-only wrapping-key diagnostic (2026-10-03)

This command checks the selected identity and active key; it is not a complete
key inventory or production-readiness check.

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

### Authenticated identity wrapping upgrade

New wrapped identities authenticate their SQLite identity key, device ID and
canonical ML-DSA public key, together with the envelope version and wrapping-key
ID. Older envelopes without this binding require an explicit upgrade before
runtime use. With the original wrapping key available, run `openclaw doctor --fix`
and review its changes and warnings. Doctor upgrades old wrapped rows, including
custom identity keys, after verifying the original public/private pair. Successful
upgrades preserve the device ID and signing keys; the wrapping upgrade is idempotent.
Then check `openclaw wrap-key status --identity-key <stored-identity-key> --json`.

Failed upgrades preserve their rows and report warnings; other valid rows may
have upgraded successfully. Authentication failures in bound envelopes require
restoring the original key or a trusted backup, rather than changing identity
metadata or regenerating a key. Legacy upgrades cannot establish whether an old
unbound row was previously moved. This binding does not prevent restoring an
entire database snapshot or replaying a row in another database with the same
identity key and wrapping key.

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
- A workflow that stops before testing provides no test result. Check the run
  and exact commit before citing it as evidence.
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
| `extensions/nostr/src/nostr-bus.ts` | Production custom PQC DM v1 transport (kind `4444`)                     |
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
