# Checkpoint 013: PeerKey Idempotency

## Decision

Duplicate `PeerKey` events with the same public key do not rebuild an established client crypto session.

If a connected peer later sends a different public key for the same client identity, the client rejects it until the protocol has an explicit rekey flow.

## Rationale

The CLI retries `PeerKey` announcements while peers start in any order. That retry behavior must not reset nonce tracking or outbound nonce counters after a session is ready.

Treating duplicate keys as idempotent keeps startup retry simple while preserving replay protection. Rejecting changed keys keeps v1 from silently accepting an identity/key change that users did not verify.

## Validation

- `cargo test -p chat-client keeps_replay_protection_after_duplicate_peer_key`
- `cargo test -p chat-client rejects_changed_peer_key_after_session_ready`
- `cargo test -p chat-client`
- `mise run verify`
