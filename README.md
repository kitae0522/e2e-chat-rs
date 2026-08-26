# e2e-chat-rs

Tiny Rust 1:1 E2E encrypted chat for learning cryptography boundaries and Event Driven Architecture.

The project is intentionally small: no accounts, database, persistence, group chat, or rich UI. The server relays encrypted events only. Clients own key exchange, encryption, decryption, nonce tracking, and plaintext display.

## Requirements

Use `mise` to install the pinned Rust toolchain:

```bash
mise install
mise run verify
```

## Run Locally

Open three terminals.

Terminal 1, start the relay:

```bash
cargo run -p chat-server
```

Terminal 2, start Alice:

```bash
cargo run -p chat-client -- --id alice --peer bob
```

Terminal 3, start Bob:

```bash
cargo run -p chat-client -- --id bob --peer alice
```

Type a message in either client and press Enter. The sender prints `message delivered to relay` when the relay accepts the encrypted message. The receiver prints decrypted plaintext.

### Verifying the peer key

By default the client displays the peer's key fingerprint (unverified). To pin it — a substituted key then never opens a session — pass the expected fingerprint:

```bash
cargo run -p chat-client -- --id alice --peer bob \
  --verify-fingerprint <64-hex-fingerprint-of-bob>
```

Compare fingerprints out of band before trusting a session.

### Rotating session keys

Either client can run `/rekey` at any time to start an ephemeral-DH handshake that rolls both peers onto a fresh session key (the next epoch):

```text
/rekey
session key rotated to epoch 1
```

To rotate periodically without typing the command, pass a message threshold:

```bash
cargo run -p chat-client -- --id alice --peer bob --rekey-after 100
```

### Custom port:

```bash
CHAT_SERVER_ADDR=127.0.0.1:3001 cargo run -p chat-server
cargo run -p chat-client -- --server ws://127.0.0.1:3001/ws --id alice --peer bob
cargo run -p chat-client -- --server ws://127.0.0.1:3001/ws --id bob --peer alice
```

## Architecture

- `chat-core`: protocol events, typed ids, nonce tracking, and E2EE crypto.
- `chat-server`: event-driven WebSocket relay with in-memory connected-client routing.
- `chat-client`: tiny CLI adapter around `ClientSession`.

Flow:

```text
stdin -> ClientSession encrypt -> WireEvent -> relay -> peer ClientSession decrypt -> stdout
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the learning notes and design boundaries.

## Development

```bash
mise run fmt
mise run check
mise run clippy
mise run test
mise run verify
```

Use TDD for feature work. Keep milestones small and record decisions in `docs/checkpoints/`.

Pull requests run the same suite in CI via GitHub Actions (`.github/workflows/verify.yml`); local `mise run verify` must pass before opening a PR.

## Current Limits

- Ephemeral identity keys only.
- No offline delivery or resend.
- Relay ACK means accepted by the relay, not read by the peer.
- Peer fingerprint verification is opt-in via `--verify-fingerprint`; without it the fingerprint is displayed but not enforced.
