# Checkpoint 012: EventHook Extension Point

## Decision

`chat-core` now defines an `EventHook` trait and `NoopEventHook` default in `chat_core::service`.

`chat-server` accepts hook implementations through `serve_with_router_and_hook`, while the existing `serve` and `serve_with_router` paths keep the default no-op behavior.

## Rationale

The framework roadmap needs observable server lifecycle events before adding auth or persistence. A synchronous hook keeps the first extension point small and avoids `async-trait`, background workers, storage, or policy decisions.

The hook contract observes:

- successful client connect
- successful client disconnect
- accepted route
- rejected route with `RouterError`

Hooks do not change routing decisions. `MessageRouter` remains responsible for routing, and future `AuthProvider` or `MessageStore` boundaries can be added without mixing policy or persistence into this hook.

## Validation

- `cargo test -p chat-server`
- `mise run verify`
