# Checkpoint 016: Typed Relay Error Code Contract

## Decision

`WireEvent::Error.code` changed from a free-form `String` to a typed `RelayErrorCode` enum in `chat-core`.

Known codes serialize as snake_case strings (`sender_mismatch`, `unknown_recipient`, `unsupported_event`, `client_not_connected`, `client_already_connected`, `connect_denied`). Codes this version does not know deserialize into `RelayErrorCode::Other(String)` and serialize back verbatim. `From<&RouterError>` and `From<&AuthError>` conversions are the only sanctioned way for producers to build codes.

## Rationale

With three extension points (router, hook, auth), error codes were being produced ad hoc via `format!("{error:?}")` — Debug-format dependent and untestable as a contract. A typed enum makes the wire contract explicit and compiler-checked.

The `Other` fallback keeps protocol evolution non-breaking for receivers: an older client that receives a code from a newer relay still parses the event instead of dropping it. The `From` conversions prevent producers from inventing codes that bypass the contract.

## Wire Format Migration

This is a breaking change to the `Error` event's `code` field (`"SenderMismatch"` Debug-style → `"sender_mismatch"` snake_case). Accepted because v1 is unreleased with no deployed clients; no compatibility shim is carried forward. From here on, changes to `code` values must be additive (new variants) to preserve the `Other` fallback guarantee.

## Validation

- `cargo test -p chat-core serializes_error_code_as_snake_case_contract`
- `cargo test -p chat-core preserves_unknown_error_codes_from_newer_peers`
- `mise run verify`
