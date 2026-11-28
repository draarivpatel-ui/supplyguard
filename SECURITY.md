# Security policy

## Reporting a vulnerability

Use the private GitHub Security Advisory form at [Report a vulnerability](https://github.com/draarivpatel-ui/supplyguard/security/advisories/new). Do not open a public issue, pull request or discussion with exploit details.

Never include a live secret, token, cookie, private key, victim hostname or proprietary payload in a report. Use synthetic values and redacted transcripts.

## Supported versions

| Version | Status |
| --- | --- |
| latest `main` | Supported |

Security fixes are applied to the latest state of the default branch.

## Scope

This policy covers the static SupplyGuard browser application, including supply-chain artifact parsing, policy evaluation, diffing, attestation output, graph rendering and export generation.

In scope:

- A cross-site scripting or HTML injection path through package metadata, lockfile content, policy output, diff output, graph labels, imports or reports.
- A parser or validation bypass that causes malformed supply-chain input to be treated as trusted or attested.
- A policy or diff calculation flaw that hides a dependency, provenance, integrity or version-change finding.
- An attestation, JSON, CSV or report export flaw that forges evidence or injects spreadsheet or markup control characters.
- A client-side persistence or share-state flaw that corrupts another analysis or executes attacker-controlled code.

Out of scope:

- Browser vulnerabilities, operating system compromise or physical access to the machine.
- Damage caused by modified copies of the static application that do not come from this repository.
- The inherent limits of user-supplied artifact evidence when the application accurately labels that evidence as unverified.

## Coordinated disclosure

- Acknowledgment: within 3 business days.
- Initial triage: within 14 calendar days.
- Fix or mitigation target: within 90 calendar days for confirmed reports.
- Coordinated public disclosure: up to 90 days by default, adjusted by mutual agreement when exploitation or user risk requires a different date.
