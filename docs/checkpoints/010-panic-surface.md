# Checkpoint 010: Panic Surface Audit

## Decision

Phase 0 keeps panic handling as an audit and guardrail step. Non-test Rust code must not introduce `unwrap()`, `expect()`, or `panic!()`.

## Rationale

The framework roadmap needs stable extension points before trait extraction. Keeping panics out of library and server/client runtime paths makes failures explicit and preserves the existing typed-error boundary.

## Audit

The audit command is:

```bash
rg -n "(unwrap\\(|expect\\(|panic!\\()" crates --glob '*.rs'
```

Current matches are confined to tests or test-only assertions. The non-test code path does not use `unwrap()`, `expect()`, or `panic!()`.

## Guardrail

Each crate root denies these clippy lints for non-test builds:

- `clippy::unwrap_used`
- `clippy::expect_used`
- `clippy::panic`

Unit and integration tests may keep explicit `expect()` and `panic!()` where they make assertions clearer.

## Validation

- `rg -n "(unwrap\\(|expect\\(|panic!\\()" crates --glob '*.rs'`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
