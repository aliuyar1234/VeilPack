# Security Policy

## Supported Versions

VeilPack currently supports:

| Version | Supported |
|---|---|
| `main` | yes |
| latest GitHub release | yes |
| older releases | best effort only |

## Reporting a Vulnerability

Please do not open a public issue for a suspected security vulnerability.

Preferred reporting path:

- use GitHub private vulnerability reporting if it is enabled for the repository

Fallback:

- contact the maintainer through GitHub at `@aliuyar1234`

Please include:

- affected version or commit
- reproduction details
- impact assessment
- whether the issue can leak plaintext sensitive data, bypass verification, or violate offline/fail-closed guarantees

## Response Goals

Best effort targets:

- initial triage acknowledgement within 7 days
- severity assessment after reproduction
- coordinated disclosure after a fix or mitigation is available

## Scope

Security reports are especially valuable for:

- fail-open parsing or transformation behavior
- residual verification bypasses
- evidence tampering or integrity gaps
- plaintext leakage in logs or evidence
- unsafe filesystem handling
- unexpected network usage
