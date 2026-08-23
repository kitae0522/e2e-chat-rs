# Checkpoint 019: Server Input Size and Queue Limits

## Decision

The WebSocket relay now enforces two explicit resource limits:

- `MAX_EVENT_BYTES` (64 KiB) — applied via axum's `max_message_size`/`max_frame_size`. Oversized frames surface as protocol errors, and both the hello phase and the event loop now close the connection on transport errors instead of skipping them.
- `OUTBOX_CAPACITY` (256) — per-client outbound queues are bounded. When a delivery hits a full queue, the relay signals that connection to close through a per-connection close channel and removes it from the connection map; the connection task exits through the normal unregister path (router disconnect + hook).

## Rationale

A slow or malicious client previously had three unbounded pressure points: payload size, JSON parse cost, and its own outbox. The outbox was an unbounded channel, so one slow reader could grow server memory without limit.

Closing a full-queue connection was chosen over dropping queued events: silent loss is indistinguishable from successful delivery in this protocol, while a closed connection is observable by the client. The close signal goes through a dedicated channel so cleanup always flows through `unregister_client`, keeping router state and hooks consistent.

## Validation

- `cargo test -p chat-server flush_outboxes_closes_slow_client_when_outbox_is_full`
- `cargo test -p chat-server --test ws_relay closes_connection_on_oversized_message`
- `mise run verify`
