# Checkpoint 005: WebSocket Server

## Decision

`chat-server` now exposes a WebSocket endpoint at `/ws`. Each connection must first send `ClientHello`, which registers the connection id with the in-memory router.

After registration, the socket task reads wire events and passes `PeerKey` or `EncryptedMessage` events to the router. Outbound events are sent through per-client channels.

## Rationale

The WebSocket layer is an adapter around the pure router. This keeps network IO separate from delivery rules:

- WebSocket task: frame parsing and socket writing
- Router: sender validation and recipient outbox selection
- Channel map: delivery from router outboxes back to active sockets

This split makes the server event-driven without hiding routing logic inside socket loops.

## Safety

The server still does not decrypt messages. It parses JSON into `WireEvent`, validates metadata through the router, and forwards ciphertext envelopes.

Forged sender metadata is rejected by the router before delivery. Unknown recipients produce a routing error instead of reaching another client.

## Current Limitation

There is no handshake acknowledgement yet. The integration test waits briefly after both `ClientHello` events so the server can register both clients before a `PeerKey` event is sent.

Later client behavior should wait for explicit readiness or peer key state instead of relying on timing.

## Scope

This checkpoint intentionally excludes encrypted chat text UX, reconnects, persistent rooms, delivery retries, and client-side session state.
