# Security Policy

## Overview

The PQC OpenClaw fork (this repository) is a production-grade post-quantum
cryptography hardening of upstream OpenClaw. We treat the cryptographic
code path as security-critical: wrap key handling, keyring providers,
side-channel resistance, and OS keyring integration are all in scope for
security review and vulnerability disclosure.

This document describes how to report a vulnerability, what versions
are eligible for fixes, and our disclosure timeline.

## Supported Versions

| Version                             | Supported | Notes                                                                |
| ----------------------------------- | --------- | -------------------------------------------------------------------- |
| `main` (latest commit)              | ✅        | All security fixes land here first.                                  |
| Tagged releases (`v1.x.y`)          | ✅        | Backports security fixes for the most recent minor.                  |
| Older minor versions                | ❌        | Upgrade to the latest `v1.x` to receive fixes.                       |
| PRs / branches under review         | ❌        | Not production targets.                                              |
| Upstream `openclaw/openclaw:master` | —         | See upstream's own security policy. This fork re-bases periodically. |

The PQC fork follows [Semantic Versioning](https://semver.org/). A
security fix that breaks the on-disk `state.db` schema, the wrap-key
envelope, or the `@napi-rs/keyring` wire format is a major-version
bump (e.g. `1.x.y` → `2.0.0`) and ships with a migration guide.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security bugs.**

Report privately to one of:

- **GitHub Security Advisories** — preferred. Use
  [the private reporting form](https://github.com/WU123-ABC-Cell/pqc-openclaw/security/advisories/new)
  on the PQC fork's GitHub repo. The maintainers receive an email
  and can coordinate disclosure.
- **Direct email** — to the maintainer listed on the GitHub org
  (`WU123-ABC-Cell`) profile. Use PGP if you have sensitive
  details; the public key is published on the maintainer's GitHub
  profile.
- **Out-of-band** — if the issue is exploitable in production and
  you need a same-day response, message a maintainer directly on
  the public OpenClaw Discord or via the security contact listed
  on the upstream project.

Please include:

1. A short description of the issue.
2. Steps to reproduce, or a proof-of-concept.
3. The affected version(s) and configuration (Node version, OS
   keyring backend, OpenSSL version).
4. Impact assessment: confidentiality / integrity / availability
   implications, and the realistic attacker model (passive disk
   thief, kernel-privileged attacker, network adversary, etc.).
5. Whether you intend to disclose publicly and on what timeline.

## Response Timeline

| Step                                        | Target                                                             |
| ------------------------------------------- | ------------------------------------------------------------------ |
| Acknowledge the report                      | within 3 business days                                             |
| Triage (severity, scope, affected versions) | within 7 business days                                             |
| Patch for the most recent `v1.x` release    | within 30 days for High / Critical; 90 days for Medium / Low       |
| Backport to older supported versions        | case-by-case, usually within the same window                       |
| Public disclosure                           | coordinated with the reporter, default 90 days after the fix lands |

Critical issues (active exploitation, wrap key disclosure, bypass of
the FIPS 203/204 implementation) get accelerated handling — we aim
for a same-day security release on confirmed critical bugs.

## Disclosure Policy

- We follow **coordinated disclosure**. We ask reporters to give us
  a reasonable window to fix the issue before publishing details.
  We reciprocate: we credit the reporter in the security advisory
  (unless they prefer anonymity) and coordinate the public
  disclosure date.
- We reserve the right to disclose immediately if the issue is
  already public, if a CVE is requested, or if we believe
  disclosure is necessary to protect users.
- **Embargoed issues** are tracked in private GitHub Security
  Advisories until the fix is released. Reporters who need
  multi-party coordination (e.g. upstream OpenClaw, NIST, OS
  vendors) can request an extended embargo; we will respect it as
  long as the disclosure remains within 120 days of the report.

## Out of Scope (please report anyway if in doubt)

The following are explicitly **not** security vulnerabilities in this
fork, but we will still accept reports and route them appropriately:

- Bugs in the **upstream OpenClaw core** (Nostr, Gateway TLS, APNs,
  plugin SDK, etc.). Please report those to upstream
  `openclaw/openclaw` instead — this fork re-bases from upstream
  periodically and we will pick up the fix.
- Side-channel findings on **third-party cryptographic libraries**
  (@noble/post-quantum 0.7.0, @napi-rs/keyring 1.3.0, OpenSSL 3.x,
  Node 24.6+ `process.mlock`). Please report those to the upstream
  maintainers; this fork re-bases after each upstream release.
- Findings on **hardware-level** cache-timing (FLUSH+RELOAD,
  PRIME+PROBE) on microarchitectures we have not tested. We list
  these in the whitepaper §6.3 honest list and consider them a
  known limitation, not a vulnerability in the fork code.
- Findings on **FIPS 140-3 certification** status. The fork relies
  on OpenSSL 3.x FIPS 140-3 validated path for AES-256-GCM. We
  explicitly do not claim FIPS 140-3 certification for the fork
  itself; that is a separate (long) process (see whitepaper §10
  future work, audit-grade backlog #3).

## Cryptographic Agility

The fork is designed for cryptographic agility:

- Algorithm selection (`@noble/post-quantum` ≥ 0.7.0) is
  centralized; a future FIPS 205 (SLH-DSA) or FIPS 206 (FN-DSA)
  algorithm can be added without rewriting the keyring or wrap
  envelope.
- Wrap-key envelope format is JSON with `ciphertext`, `iv`,
  `authTag`, `keyId` fields. The on-disk `BLOB` column in
  `state.db` is a base64url-encoded JSON. New key types can be
  added by extending the envelope and bumping the version field.
- Side-channel test scripts in `pqc-fork-scripts/` are
  algorithm-agnostic. Adding a new algorithm (e.g. SLH-DSA) just
  means adding a new driver line.

This means a future cryptographic break (e.g. a practical attack
on ML-KEM-768) can be remediated by a key rotation + algorithm
swap, with no on-disk migration beyond updating the wrap envelope.

## Reporting a Non-Security Issue

For non-security bugs (typos, UX issues, performance problems),
please open a public GitHub issue on the PQC fork.

## Recognition

We follow a **hall of fame** model: every reporter who discloses a
vulnerability is credited in the security advisory (unless they
prefer anonymity). High-impact findings may receive a small bug
bounty; we are not currently funded for a paid program, but the
fork welcomes donations to enable one in the future.

## Contact

- GitHub Security Advisories: <https://github.com/WU123-ABC-Cell/pqc-openclaw/security/advisories/new>
- Maintainer: see `WU123-ABC-Cell` GitHub org

---

This policy is modelled on the
[GitHub Security Lab's recommended disclosure template](https://github.com/github/.github/blob/main/SECURITY.md)
and is licensed under [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/).
