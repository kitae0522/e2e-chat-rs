# Checkpoint 003: Crypto Session

## Decision

`chat-core` now owns pairwise cryptographic sessions. A `KeyPair` creates an X25519 public/private key pair, and `CryptoSession` derives a shared symmetric encryption context from the local private key and peer public key.

Messages use XChaCha20-Poly1305 for authenticated encryption. The encrypted output is still an `EncryptedEnvelope`, so the server can route it without plaintext access.

## Rationale

X25519 is used for key agreement because two clients can derive the same shared secret without sending that secret over the network. HKDF-SHA256 turns that shared secret into a purpose-specific AEAD key.

XChaCha20-Poly1305 is used because it provides authenticated encryption and a 24-byte nonce. The larger nonce size makes accidental nonce collision less likely than shorter nonce designs, while keeping the API simple for this learning project.

## Associated Metadata

The AEAD associated data includes:

- protocol version
- sender id
- recipient id
- message id

Associated data is not encrypted, but it is authenticated. If a network attacker changes the message id or other bound metadata, decryption fails.

## Nonce Safety

`NonceTracker` records seen nonces for a session and rejects duplicates. This is separate from encryption so the client can decide when to mark inbound or outbound nonces as used.

## Server Boundary

The server still has no crypto API. It should only validate routing metadata and relay ciphertext envelopes. This keeps E2EE responsibility in the client/shared core instead of turning the server into a trust authority.

## Scope

This checkpoint intentionally excludes automatic key verification, Double Ratchet, persistent identities, WebSocket routing, and CLI behavior.
