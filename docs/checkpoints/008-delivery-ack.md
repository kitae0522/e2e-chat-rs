# Checkpoint 008: Relay Delivery ACK

## Decision

The relay now returns `Ack` to the sender after it accepts an `EncryptedMessage` and places it in the recipient outbox. The CLI prints this control event to stderr as:

```text
message delivered to relay
```

## Rationale

In a chat system, "encrypted locally" and "accepted by the relay" are different events. The ACK makes that boundary visible without adding accounts, persistence, or a complex delivery protocol.

This is still not a read receipt. It only means the relay accepted the message for a connected recipient.

## Safety

The router emits ACKs only after normal validation succeeds:

- sender id must match the WebSocket connection
- recipient must be connected
- event must be an `EncryptedMessage`

Rejected messages do not receive ACKs.

The WebSocket layer reports routing failures for encrypted messages. It suppresses `UnknownRecipient` errors for `PeerKey` retries, because periodic public-key announcements are expected before both peers are online.

## Validation

- Red test: `acks_accepted_encrypted_message_to_sender_outbox`
- Red test: `describes_ack_as_relay_delivery_status`
- Red test: `suppresses_unknown_recipient_error_for_peer_key_retry`
- `mise run test -- -p chat-client`
- `mise run test -- -p chat-server`
- Live smoke test with one server and two clients on `127.0.0.1:3001`

## Scope

This checkpoint intentionally excludes durable offline delivery, message resend, client-side pending message tracking, and peer read receipts.
