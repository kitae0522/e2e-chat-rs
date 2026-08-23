# Checkpoint 014: Server Builder API

## Decision

`chat-server::ws` now exposes a `WsServer` builder with `InMemoryRouter` and `NoopEventHook` defaults.

Routers and hooks are injected by chaining `with_router` and `with_hook`, and the server runs with `run(listener-bound)`. The existing `serve`, `serve_with_router`, and `serve_with_router_and_hook` entry points remain and delegate to the builder.

## Rationale

The `serve*` function family grew one signature per extension point (`serve_with_router`, then `serve_with_router_and_hook`). Adding an auth provider or storage boundary this way would keep multiplying combinations. The builder freezes the injection path so future extension points (see `docs/todo.md`: AuthProvider, MessageStore) attach as one additional `with_*` method instead of a new function signature.

## Validation

- `cargo test -p chat-server --test ws_relay`
- `mise run verify`
