# Compatibility Matrix

This matrix defines which pack metadata versions are accepted by `veil verify`.

## Verified Combinations
| pack_schema_version | ledger_schema_version | Supported |
|---|---|---|
| `pack.v1` | `ledger.v1` | yes |
| `pack.v0` | `ledger.v1` | no |
| `pack.v1` | `ledger.v0` | no |

## Policy
- Compatibility is explicit and versioned.
- Unsupported combinations fail closed with exit code `1`.
- New supported combinations must be added here and covered by `crates/veil-cli/tests/compatibility_matrix.rs`.

## Migration Discipline
- Backward compatibility changes require:
  - matrix update in this file,
  - regression tests in `crates/veil-cli/tests/compatibility_matrix.rs`,
  - a release-note entry explaining upgrade/rollback behavior.
