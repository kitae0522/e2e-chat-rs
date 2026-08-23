# Checkpoint 018: ClientId Input Policy

## Decision

`ClientId::parse` now enforces an explicit contract: 1–64 characters, ASCII letters/digits plus `-`, `_`, `.` only. Whitespace, control characters, and non-ASCII characters are rejected. `TypeError` gained `ClientIdTooLong` and `ClientIdInvalidCharacter`; `EmptyClientId` remains for empty input.

## Rationale

`ClientId` routes envelopes and is bound into AEAD associated data, but validation previously only rejected blank-after-trim — and stored the untrimmed original, a silent mismatch between check and value. Rejecting instead of normalizing keeps the wire id identical to the id every peer saw; trimming would let two users collide on the same routed identity.

The allowed set is deliberately minimal: ASCII-only avoids unicode confusables and encoding surprises in routing maps and logs. The wire format itself is unchanged (ids remain JSON strings) — only validation tightened. Existing ids used by tests and examples (`alice`, `bob`, …) all satisfy the policy.

## Behavior Change

`" "` (whitespace-only) now fails with `ClientIdInvalidCharacter` instead of `EmptyClientId`. Both were rejections before; only the error variant differs.

## Validation

- `cargo test -p chat-core rejects_ids_with_whitespace_instead_of_trimming`
- `cargo test -p chat-core rejects_client_id_longer_than_limit`
- `mise run verify`
