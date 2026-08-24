# Checkpoint 022: Rekey Handshake State Machine (Rekey Phase 2)

## Decision

`CryptoSession` now supports an authenticated rekey handshake:

- `SessionPayload` enum (`Chat`, `RekeyRequest`, `RekeyResponse`) serializes inside `EncryptedEnvelope` ciphertext — control messages ride the encrypted channel and inherit its authentication.
- Master secret chaining: `master' = HKDF-Extract(salt = master, IKM = ephemeral DH)`, then per-epoch keys derive from the new master. The previous master is zeroized.
- API: `start_rekey()` (initiator), `handle_session_payload()` (both roles), `commit_staged_rekey()` (responder), `encrypt_payload`/`decrypt_payload`.
- The responder **stages** its rotation until after it has encrypted the reply at the old epoch, then commits. The initiator switches upon processing the response.

Design: `docs/superpowers/specs/rekey-design.md`.

## Rationale

Encrypting handshake messages under the current session key means only key holders can initiate or answer a rekey — no separate authentication mechanism needed.

The staged responder rotation fixes a flow defect found during TDD: switching before sending the response would encrypt the response under an epoch the initiator cannot yet read (`UnknownEpoch`). The implementation therefore mirrors the corrected design: response travels under the old epoch, dual-epoch reception (checkpoint 021) covers the skew until both sides converge on epoch+1.

Chaining through the old master preserves the authentication property across generations: future keys are unreachable without the current session key. Nonce counters never reset across epochs, so nonce reuse under a rotated key is impossible by construction.

## Validation

- `cargo test -p chat-core completes_rekey_handshake_and_advances_both_epochs`
- `cargo test -p chat-core rejects_rekey_response_with_unknown_rekey_id`
- `cargo test -p chat-core rejects_rekey_request_while_handshake_in_progress`
- `mise run verify` (73 tests)
