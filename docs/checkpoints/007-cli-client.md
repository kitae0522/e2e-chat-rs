# Checkpoint 007: Tiny CLI Client

## Decision

`chat-client` is now a small terminal client. It parses `--server`, `--id`, and `--peer`, connects to the WebSocket relay, sends `ClientHello`, announces its public key, reads stdin, encrypts lines, and prints decrypted inbound messages.

Example:

```bash
cargo run -p chat-client -- --id alice --peer bob
```

## Rationale

The CLI stays thin on purpose. Terminal IO and WebSocket IO live in `main.rs`; E2EE state stays in `ClientSession`. This keeps the cryptographic rules reusable and easy to test without requiring a running terminal client.

The client uses `tokio::select!` because it has three event sources:

- stdin lines from the user
- inbound WebSocket messages from the relay
- periodic public-key announcements

This is the smallest practical Event Driven Architecture for the client.

## Safety

Plaintext is never sent to the server. Outbound stdin lines become `EncryptedMessage` events through `ClientSession::encrypt_line`.

The client keeps announcing its public key once per second. This is not secret data, and it avoids startup-order failure when one peer connects before the other. A later version should replace this with an explicit key ACK event.

Inbound events are passed through `ClientSession::handle_event`. The CLI prints only returned plaintext, so parse errors, wrong peer keys, duplicate nonces, and failed decryptions do not become chat output.

## Validation

- `mise run test -- -p chat-client`
- Live smoke test with one server and two clients on `127.0.0.1:3001`
- Alice to Bob: `hello bob`
- Bob to Alice: `hi alice`

## Scope

This checkpoint intentionally excludes reconnects, delivery receipts, persisted identity keys, peer fingerprint verification, and a rich terminal UI.
