# Checkpoint 021: Session Epoch Foundation (Rekey Phase 1)

## Decision

`EncryptedEnvelope` gains an `epoch: u32` field bound into the AEAD associated data. `CryptoSession` derives per-epoch keys (`HKDF(shared_secret, session_info || epoch)`), encrypts outbound at its current epoch, and accepts inbound envelopes at the current or immediately previous epoch only (`CryptoError::UnknownEpoch` otherwise). Inbound replay tracking is per-epoch.

Design: `docs/superpowers/specs/rekey-design.md` (issue #46).

## Rationale

The epoch field is the foundation the rekey handshake needs: without a generation marker in every envelope, neither peer could tell which key a message was encrypted under during a transition. Binding it into the AAD prevents an attacker from relabeling an old-generation message as current (and vice versa) — flipping the field fails authentication under the claimed epoch's key.

Accepting exactly one previous epoch gives at-most-one-generation slack for in-flight messages across a key switch, with no timers or acknowledgments. Replay tracking stays per-epoch because nonce reuse rules are generation-scoped once keys rotate.

This phase deliberately ships without the handshake itself; `bump_epoch_for_test` exercises the transition paths until the real state machine (phase 2) replaces it.

## Wire Format Migration

Breaking change: `EncryptedEnvelope` JSON gains an `epoch` integer and the session key derivation now mixes the epoch into HKDF `info`. Accepted under the unreleased-v1 precedent (checkpoints 016/020).

## Validation

- `cargo test -p chat-core binds_epoch_into_associated_data`
- `cargo test -p chat-core accepts_previous_epoch_only_during_transition`
- `mise run verify`
