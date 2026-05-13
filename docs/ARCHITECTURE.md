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

## Safety Checks

- forged sender ids are rejected by the router
- unknown encrypted-message recipients are reported to the sender
- unknown `PeerKey` recipients are suppressed during retry
- duplicate `PeerKey` events do not reset an established client crypto session
- changed peer keys are rejected until an explicit rekey protocol exists
- duplicate inbound nonces are rejected by the crypto session
- tampered ciphertext or authenticated metadata fails decryption

## Why Not More?

No accounts, persistence, reconnect protocol, group chat, or rich UI are included in v1. Those features are useful later, but they would hide the core lessons: typed protocol events, explicit state machines, and E2EE boundaries.
