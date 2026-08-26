# Checkpoint 024: Automatic Rekey Trigger

## Decision

`ClientSession::set_auto_rekey_after(n)` enables periodic key rotation: once `n` outbound messages have been sent since the last completed rekey, the next `encrypt_line` appends a rekey request envelope after the chat envelope. The counter resets when the handshake completes (`RekeyCompleted`). While a handshake is in progress, auto-trigger is skipped rather than erroring. The CLI exposes this as an optional `--rekey-after <n>` flag (default: disabled).

## Rationale

Manual `/rekey` alone means keys rotate only when users remember to. A message-count threshold gives long conversations forward-secret rotation without user attention.

Design choices:

- The rekey request rides **after** the threshold chat envelope, so the triggering message itself still goes out at the current epoch — no message is delayed or dropped by rotation.
- Skipping while a handshake is pending keeps the feature silent under slow handshakes; the counter simply continues and triggers on the next eligible send.
- Counting resets only on completion, not on start, so an aborted handshake retries on the next threshold hit instead of silently disabling rotation for another n messages.

`encrypt_line` now returns `Vec<WireEvent>` — the smallest shape that can express "this input produced a message plus control traffic" without buffering state in the session.

## Validation

- `cargo test -p chat-client appends_rekey_request_after_threshold_outbound_messages`
- `cargo test -p chat-client skips_auto_rekey_while_handshake_is_in_progress`
- `mise run verify` (77 tests)
