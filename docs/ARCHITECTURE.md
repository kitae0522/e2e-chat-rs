# Architecture Notes

## Goal

This project teaches a minimal E2E chat system. The main idea is separation of responsibility:

- clients can see plaintext
- the server cannot see plaintext
- protocol events are explicit data
- IO layers only move events

That boundary makes the system easier to test and reason about.

## Crate Boundaries

`chat-core` owns reusable protocol and safety logic. It defines `WireEvent`, typed values such as `ClientId`, `MessageId`, `NonceBytes`, the crypto session, the `MessageRouter` service contract, and the `EventHook` observation contract.

`chat-server` owns relay behavior. It accepts WebSocket connections, registers connected clients, routes `PeerKey` and `EncryptedMessage` events through a `MessageRouter` implementation, emits `Ack` after accepting encrypted messages, and can notify an `EventHook` implementation about connection and route outcomes. The default router is `InMemoryRouter`, and the default hook is no-op.

`chat-client` owns terminal behavior. It parses CLI args, connects to the relay, reads stdin, and prints output. It delegates E2EE state to `ClientSession`.

## Event Driven Flow

The CLI waits on three event sources with `tokio::select!`:

- stdin line from the user
- inbound WebSocket event from the relay
- periodic public-key retry timer

This is the smallest useful Event Driven Architecture in the project. Each event is handled by one branch and then converted into the next event.

## E2EE Boundary

The server receives JSON `WireEvent`s. For messages, it only sees:

- sender id
- recipient id
- message id
- nonce
- ciphertext

It never receives plaintext. Decryption happens only inside the receiving client's `ClientSession`.

## Delivery Semantics

`Ack` means the relay accepted an encrypted message for a connected recipient. It does not mean the recipient read the message, stored the message, or can recover it after disconnect.

This keeps v1 tiny while making the delivery boundary visible.

## Extension Points

`MessageRouter` decides how connected clients and outboxes are managed.
`EventHook` observes successful connects, disconnects, accepted routes, and rejected routes.

Hooks are observational only. They do not authorize, reject, store, mutate, or retry events. Auth and persistence are separate future boundaries.

## Resource Limits

The relay accepts only small E2EE control events and chat messages; file or
media transfer is out of scope for v1 and must revisit these limits.

- WebSocket message size: 64 KiB (`MAX_EVENT_BYTES`). Larger frames are a
  protocol violation and close the connection.
- Per-client event queue: 256 events (`OUTBOX_CAPACITY`). When a slow client's
  outbox is full, the relay closes that connection instead of dropping events
  silently.

## Wire Serialization Policy

Byte-carrying wire fields (`PublicKeyBytes`, `NonceBytes`, `Ciphertext`) are
encoded as standard-alphabet base64 strings inside the JSON events — not JSON
number arrays, which cost roughly twice the encoded size.

- Encoding: `base64::engine::general_purpose::STANDARD` (with padding)
- Decoding rejects invalid base64 and wrong decoded lengths
- The transport stays JSON over WebSocket text frames; a binary/Protobuf
  transport is a deliberate future migration and must be documented as a wire
  format change when attempted.

## Client Identity Policy

`ClientId` is a protocol-sensitive value: it routes envelopes and is bound into
AEAD associated data. Validation rejects rather than normalizes, so the id on
the wire always matches the id every peer saw.

- 1 to 64 characters
- ASCII letters, digits, `-`, `_`, `.` only
- no whitespace, control characters, or non-ASCII characters

## Safety Checks

- forged sender ids are rejected by the router
- unknown encrypted-message recipients are reported to the sender
- unknown `PeerKey` recipients are suppressed during retry
- duplicate `PeerKey` events do not reset an established client crypto session
- changed peer keys are rejected; recovery is an explicit user action pinned to the new fingerprint
- peer keys can be pinned via `--verify-fingerprint`; a key whose fingerprint differs from the pin never opens a session
- rekey handshakes ride inside the encrypted session and chain the master secret to a fresh ephemeral DH (`/rekey`)
- envelopes carry an epoch bound into the AEAD associated data; only the current or previous epoch decrypts
- duplicate inbound nonces are rejected by the crypto session
- tampered ciphertext or authenticated metadata fails decryption

## Known Limitations

These are accepted v1 boundaries, but they become real risks once the related
features are attempted. They are recorded so that future work starts from an
honest baseline.

- **No peer authentication unless pinned.** The `PeerKey` exchange is still
  unauthenticated by default, and a client accepts the first key it receives
  for its peer. Passing `--verify-fingerprint <hex>` pins the expected peer
  fingerprint so substituted keys are rejected; without it, the client only
  displays the received fingerprint for manual out-of-band comparison.
  A default-on verification flow remains tracked as future work.
- **Nonce reuse if static keys persist.** Outbound nonces use an in-memory
  counter that starts at zero, while the session key derives from a long-term
  X25519 shared secret. If keypairs are ever persisted across restarts, the
  counter resets but the key does not, which reuses nonces under the same AEAD
  key. Any key persistence feature must redesign nonce management first.
- **Offline messages are silently lost.** The relay stores nothing. Messages
  routed to a disconnected recipient fail with `UnknownRecipient`, and outbox
  contents are dropped when a client disconnects. Reliable delivery requires
  an explicit persistence or reconnect design.

## Why Not More?

No accounts, persistence, reconnect protocol, group chat, or rich UI are included in v1. Those features are useful later, but they would hide the core lessons: typed protocol events, explicit state machines, and E2EE boundaries.
