# Checkpoint 017: Client Peer Key Fingerprint Verification

## Decision

`chat-core::crypto` now exposes `fingerprint(&PublicKeyBytes) -> String` — SHA-256 over the raw key bytes as lowercase hex.

`ClientSession` gained an optional verification boundary: `expect_peer_fingerprint` pins the expected peer fingerprint, and inbound `PeerKey` events are checked before any session state changes. A mismatch returns `ClientSessionError::PeerKeyFingerprintMismatch` and the session stays not-ready. `peer_fingerprint()` reports the accepted key's fingerprint for display.

The CLI accepts `--verify-fingerprint <hex>` (validated: exactly 64 hex characters, case/whitespace normalized). When pinned, the ready transition reports "verified"; otherwise it displays the fingerprint with an explicit "unverified" warning.

## Rationale

This closes the largest known v1 limitation (see `docs/ARCHITECTURE.md`): an unauthenticated `PeerKey` exchange let a man-in-the-middle substitute keys undetected. Verification stays manual per the v1 decision — users compare fingerprints out of band, or pin one via the CLI flag.

The check runs before storing the key or building the crypto session, so a rejected key leaves no state behind; a later key matching the pinned fingerprint is still accepted. Without a pin, behavior is unchanged apart from surfacing the unverified fingerprint to the user, keeping the opt-in boundary honest about what is and is not protected.

## Validation

- `cargo test -p chat-client rejects_mismatched_fingerprint_and_stays_unready`
- `cargo test -p chat-client accepts_peer_key_matching_expected_fingerprint`
- `mise run verify`
