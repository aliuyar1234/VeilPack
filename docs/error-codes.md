# Error Codes

VeilPack emits structured JSON logs on stderr. `reason_code` is part of the stable operational contract.

## CLI-Level Codes
| reason_code | Meaning |
|---|---|
| `USAGE` | Invalid CLI usage or invalid user-supplied input bundle/flags |
| `INTERNAL_ERROR` | Fatal runtime failure in processing, persistence, or verification path |
| `CONFIG_IGNORED` | Non-fatal warning for accepted config that is not active in current baseline mode |

## Artifact Quarantine Codes
| reason_code | Meaning |
|---|---|
| `UNSUPPORTED_FORMAT` | Artifact type or decoded content is unsupported by current extractors |
| `ENCRYPTED` | Encrypted input that cannot be processed in fail-closed mode |
| `PARSE_ERROR` | Syntax/parse failure for declared format |
| `LIMIT_EXCEEDED` | Safety limit exceeded (size, expansion, runtime limit) |
| `UNSAFE_PATH` | Unsafe path/symlink/traversal detected |
| `UNKNOWN_COVERAGE` | Extractor emitted coverage with unknown surface status |
| `VERIFICATION_FAILED` | Residual verification detected remaining sensitive content |
| `INTERNAL_ERROR` | Internal processing failure for a specific artifact |

## Stability Guard
- Mapping is locked by tests in `crates/veil-cli/tests/error_codes.rs`.
