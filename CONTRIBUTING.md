# Contributing

Thanks for contributing to VeilPack.

## Ground Rules

- Keep the project offline-first and fail-closed.
- Preserve deterministic output behavior unless the contract change is intentional, documented, and tested.
- Prefer small, reviewable pull requests.
- Use Conventional Commits for commit messages.

## Local Setup

Prerequisites:

- Rust stable
- Python 3

Recommended first run:

```bash
cargo build --workspace
cargo test --workspace
python checks/offline_enforcement.py
python checks/boundary_fitness.py
python checks/compatibility_matrix_check.py
```

## Before Opening a Pull Request

Run the full local gate:

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo test --workspace
python checks/offline_enforcement.py
python checks/boundary_fitness.py
python checks/compatibility_matrix_check.py
```

If your change affects performance-sensitive paths, also run:

```bash
python checks/perf_harness.py --build --tolerance 0.20 --samples 3
```

## Pull Request Expectations

- Add or update tests with the change.
- Update docs when behavior or contracts change.
- Keep security-sensitive behavior explicit in code and docs.
- Avoid unrelated refactors in the same PR unless they are required for the fix.

`main` is intended to stay protected and green:

- open a pull request instead of pushing directly
- wait for GitHub Actions `CI`
- resolve review comments and conversations before merge

## Security-Sensitive Changes

Extra care is required for changes in these areas:

- extractor behavior
- residual verification semantics
- evidence and manifest contracts
- schema/version compatibility
- offline enforcement and boundary checks

When changing any of those, include:

- a clear rationale
- regression coverage
- doc updates for the new contract

## Compatibility and Schema Changes

If you change pack or ledger compatibility behavior:

- update [docs/compatibility-matrix.md](docs/compatibility-matrix.md)
- update `crates/veil-cli/tests/compatibility_matrix.rs`
- document upgrade and rollback expectations

## Release Process

Tagged releases are automated through GitHub Actions.

- Create and push a semantic tag like `v1.1.0`
- The `Release` workflow builds platform artifacts and publishes a GitHub release
- Release notes are generated from the tag automatically

For manual recovery or re-publication, use the `Release` workflow with `workflow_dispatch` and an existing tag.
