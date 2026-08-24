# Checkpoint 023: Client Rekey Integration (Rekey Phase 3)

## Decision

`ClientSession` now speaks `SessionPayload` end to end:

- `encrypt_line` wraps text as `SessionPayload::Chat`; inbound envelopes are decrypted via `decrypt_payload`.
- An inbound `RekeyRequest` is answered automatically (only session-key holders can produce one) — the reply is encrypted at the old epoch and the responder's staged rotation commits immediately after.
- A completed handshake surfaces as `InboundEvent::RekeyCompleted { epoch }`, printed by the CLI as "session key rotated to epoch N".
- The `/rekey` stdin command starts a handshake (`ClientSession::start_rekey`), refused before the session is established.

## Rationale

This completes the rekey flow from the design doc: a user can rotate session keys with `/rekey`, and both peers converge on epoch+1 with dual-epoch reception absorbing in-flight messages. Automatic response is safe because forging a request requires the current session key.

A changed long-term peer key still terminates the session with a fingerprint mismatch; recovery remains an explicit user action (restart pinned to the new fingerprint) per the no-silent-swap rule in the design doc. Automatic rekey triggers remain future work, as recorded there.

## Validation

- `cargo test -p chat-client completes_rekey_handshake_from_inbound_request_and_replies`
- `cargo test -p chat-client encrypts_and_decrypts_line_after_peer_key_exchange`
- `mise run verify` (74 tests)
