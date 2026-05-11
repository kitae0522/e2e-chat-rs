# Checkpoint 004: In-Memory Router

## Decision

`chat-server` now has an `InMemoryRouter` that tracks connected clients and queues outbound `WireEvent` values in per-client outboxes.

The router handles `PeerKey` and `EncryptedMessage` events. It rejects events when the connection id does not match the event sender, or when the recipient is not connected.

## Rationale

Routing is pure application logic, so it should be testable without sockets. Keeping the router separate from WebSocket code makes the event-driven architecture easier to understand:

- connection tasks handle network IO
- the router owns delivery rules
- outboxes hold events waiting for each recipient

This split keeps future WebSocket code thin and makes routing behavior deterministic in unit tests.

## Safety

The router validates sender and recipient metadata, but it does not decrypt or inspect ciphertext. That preserves the E2EE boundary: the server may know who should receive an envelope, but not what the message says.

Forged sender metadata is rejected before the event reaches another client's outbox. Unknown recipients are rejected instead of silently dropping events.

## Scope

This checkpoint intentionally excludes WebSocket connections, delivery acknowledgements, retry logic, persistence, and client session behavior.
