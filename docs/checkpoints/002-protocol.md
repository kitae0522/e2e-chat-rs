# Checkpoint 002: Protocol Events

## Decision

The shared protocol lives in `chat-core`. Network messages are represented as typed `WireEvent` values, and protocol-sensitive fields use newtypes such as `ClientId`, `MessageId`, `NonceBytes`, `PublicKeyBytes`, and `Ciphertext`.

## Rationale

The server and client must agree on event shapes before either side owns network behavior. Keeping these types in `chat-core` gives both applications one reusable contract.

Newtypes keep plain strings and byte vectors from being mixed accidentally. For example, a `NonceBytes` value and a `PublicKeyBytes` value are both byte arrays, but they mean different things and have different sizes.

## Serialization

Events serialize as JSON with an explicit `type` field. JSON keeps the early protocol inspectable while the system is still small and educational.

`PeerKey` includes both `from` and `to` so key announcements are bound to sender and recipient metadata. `EncryptedMessage` uses an `EncryptedEnvelope` so ciphertext and routing metadata travel together.

## Safety

`ClientId` rejects empty values at construction and deserialization. `EncryptedMessage` has no plaintext field, which keeps the server-facing event shape aligned with the E2EE design.

This checkpoint does not provide cryptographic authentication yet. Metadata tamper resistance will be added when encryption binds sender, recipient, message id, and protocol version as AEAD associated data.

## Scope

This checkpoint intentionally excludes key generation, encryption, nonce tracking, routing, WebSocket handling, and CLI behavior.
