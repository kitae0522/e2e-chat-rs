# Checkpoint 011: MessageRouter Trait Entry

## Decision

`chat-core` now defines the `MessageRouter` trait and shared `RouterError` contract in `chat_core::service`.

`chat-server` keeps `InMemoryRouter` as the default implementation, while the WebSocket layer accepts any `MessageRouter` implementation through `serve_with_router`.

## Rationale

The framework roadmap needs a real extension point before adding hooks, auth, or storage. Keeping the trait in `chat-core` lets future server adapters reuse the same routing contract without depending on `chat-server` internals.

The trait preserves the current v1 semantics:

- `connect` registers a connected client
- `disconnect` removes a connected client
- `route` accepts routable `WireEvent`s from the active connection
- `drain_outbox` returns queued outbound events for a client

## Related Phase 0 Cleanup

Before introducing the trait, Phase 0 tightened two boundaries:

- outbox flush now collects sender snapshots and drained events before sending outside lock scope
- `CryptoSession` now owns outbound nonce generation and inbound replay nonce rejection

## Validation

- `cargo test -p chat-server`
- `cargo test --workspace`
- `mise run verify`
