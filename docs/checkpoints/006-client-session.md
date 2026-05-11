# Checkpoint 006: Client Session

## Decision

`chat-client` now has a `ClientSession` that owns local client state: identity, peer identity, generated keypair, optional crypto session, inbound nonce tracker, and outbound nonce counter.

The session can build `ClientHello` and `PeerKey` events, accept a peer key event, encrypt outbound text lines, and decrypt inbound encrypted messages.

## Rationale

Client behavior is split away from terminal and WebSocket IO. This keeps the important E2EE state machine testable without a running server or a human typing into stdin.

The CLI can later become a thin shell:

- read line from stdin
- call `ClientSession::encrypt_line`
- send returned `WireEvent`
- pass inbound `WireEvent` to `ClientSession::handle_event`
- print decrypted messages only

## Safety

The session rejects peer key events that do not match the expected peer and local ids. Encrypted messages are decrypted only after a peer key has initialized the crypto session.

Inbound nonces are tracked after successful decryption. Duplicate nonces are rejected before plaintext is returned to the caller.

Outbound nonces use a monotonic counter for v1. This is simple and deterministic, but it assumes the session is ephemeral and not persisted across restarts.

## Scope

This checkpoint intentionally excludes terminal UI, WebSocket connection management, peer fingerprint display, persisted identities, and reconnect behavior.
