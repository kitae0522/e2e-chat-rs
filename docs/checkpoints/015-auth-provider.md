# Checkpoint 015: AuthProvider Extension Point

## Decision

`chat-core` now defines an `AuthProvider` trait, a `NoopAuthProvider` default, and a typed `AuthError` in `chat_core::service`.

The `WsServer` builder accepts auth implementations through `with_auth_provider`. After reading `ClientHello` and before registration, the server calls `authorize_connect`; a denied client receives a `WireEvent::Error` and the connection is closed without registering.

## Rationale

Following `MessageRouter` (checkpoint 011) and `EventHook` (checkpoint 012), auth is the next framework boundary named in `docs/todo.md`. Keeping it a synchronous trait avoids `async-trait`, and keeping it at the connection level matches v1's "connection identity plus manual fingerprint verification" decision — no accounts or credentials exist yet.

Authorization runs before routing so denied identities never reach the router, the hook, or any peer's outbox. Rejection is reported on the wire instead of failing silently so clients can distinguish denial from transport failure.

## Validation

- `cargo test -p chat-server --test ws_relay builder_injects_auth_provider_and_rejects_denied_clients`
- `mise run verify`
