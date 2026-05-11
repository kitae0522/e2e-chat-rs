# E2E Chat Design

## Purpose

Build a tiny Rust chat system for learning end-to-end encryption and event-driven architecture. The project should stay small enough to read in one sitting, but structured so the protocol, crypto, client, and server can later become reusable framework pieces.

## V1 Scope

V1 supports 1:1 chat only. There are no accounts, databases, group chats, message history, file attachments, push notifications, or rich UI. The server is a relay and never receives plaintext. The CLI client owns key generation, peer verification, encryption, decryption, and message display.

This limited scope is intentional: pairwise chat is the smallest useful E2EE system, and it avoids group key management while still teaching network events, authenticated encryption, and relay design.

## Architecture

Use a Cargo workspace with three crates:

- `chat-core`: shared protocol events, typed envelopes, crypto helpers, validation errors, and test fixtures.
- `chat-server`: event-driven WebSocket relay that accepts clients, tracks online peer routes, validates envelope structure, and forwards ciphertext.
- `chat-client`: tiny CLI client that connects to the server, performs peer key exchange, encrypts outbound messages, and decrypts inbound messages.

The dependency direction is one way: server and client depend on `chat-core`; `chat-core` depends on no application crate. This keeps reusable logic portable.

## Project Setup Baseline

Before implementing protocol or crypto behavior, initialize the repository as a small Rust workspace with explicit conventions:

```text
Cargo.toml
mise.toml
rustfmt.toml
.cargo/config.toml
crates/
  chat-core/
  chat-server/
  chat-client/
docs/
  checkpoints/
  protocol.md
```

Use Rust 2024 edition. Manage the Rust toolchain and project tasks through `mise.toml`; do not add `rust-toolchain.toml`. Pin Rust to `1.95.0`, the current stable release checked on 2026-05-11, and set each crate's `rust-version` to `1.95`. If the project later becomes a framework, revisit MSRV as a deliberate compatibility decision.

The root `Cargo.toml` should be a virtual workspace with `resolver = "3"` because Rust 2024 implies the Rust-version-aware resolver for packages, while virtual workspaces should state the resolver explicitly. Keep all production crates under `crates/` to make future framework extraction straightforward.

`mise.toml` should own repeatable commands:

```toml
[tools]
rust = { version = "1.95.0", profile = "default", components = "rustfmt,clippy" }

[tasks.fmt]
description = "Check Rust formatting"
run = "cargo fmt --all -- --check"

[tasks.fmt-fix]
description = "Format Rust code"
run = "cargo fmt --all"

[tasks.check]
description = "Type-check the workspace"
run = "cargo check --workspace"

[tasks.clippy]
description = "Lint the workspace"
run = "cargo clippy --workspace --all-targets --all-features -- -D warnings"

[tasks.test]
description = "Run all tests"
run = "cargo test --workspace"

[tasks.verify]
description = "Run the full local verification suite"
run = [
  { task = "fmt" },
  { task = "check" },
  { task = "clippy" },
  { task = "test" },
]
```

`rustfmt.toml` should set `style_edition = "2024"` so editor formatting and `cargo fmt` agree. The workspace lint baseline should forbid `unsafe_code`; this project does not need unsafe Rust for its own code.

Initial dependency choices:

- workspace: `thiserror`, `serde`, `serde_json`, `uuid`, `base64`
- async/network: `tokio`, `axum`, `futures`, `tokio-tungstenite`
- crypto: `x25519-dalek`, `chacha20poly1305`, `hkdf`, `sha2`, `rand_core`, `zeroize`
- app/error/logging: `anyhow` for binaries only, `tracing`, `tracing-subscriber`
- client CLI: `clap`
- tests: Rust unit/integration tests first; add no heavy test framework unless needed

Project commands should be stable from the first milestone:

- `mise install`
- `mise run test`
- `mise run verify`

Setup intentionally excludes Docker, databases, CI, runtime config files, persistent identities, and UI dependencies. Those add operational noise before the core E2EE and event model are understood.

## Code Clarity Baseline

Prefer plain data types and small modules before traits. Add a trait only when there are at least two real implementations or when it isolates a boundary that tests need to drive, such as an event sink or clock. Use newtypes for protocol-sensitive values like `ClientId`, `MessageId`, `Nonce`, `PublicKeyBytes`, and `Ciphertext` so routing metadata and plaintext cannot be mixed accidentally.

`chat-core` should expose typed errors with `thiserror`; binaries may wrap top-level failures with `anyhow`. Public protocol types should derive useful standard traits where safe, such as `Debug`, `Clone`, `PartialEq`, `Eq`, `Serialize`, and `Deserialize`. Do not use `unwrap`, `expect`, or `panic` in production paths for network input, crypto input, or user input. Tests may use `expect` with messages when it makes failures clearer.

Keep functions short and named by behavior. Comments should explain protocol or safety intent, not restate the code. Every milestone checkpoint must document why each boundary exists and what was intentionally kept simple.

## Event Model

All network traffic is represented as explicit events. Initial events:

- `ClientHello`: announces client id and ephemeral public key.
- `PeerKey`: forwards a peer public key to another client.
- `EncryptedMessage`: carries ciphertext, nonce, sender id, recipient id, and message id.
- `Ack`: confirms the relay accepted or delivered an event.
- `Error`: reports malformed, unauthorized, or unroutable events.

The server treats events as routing data. It validates that required fields exist and that the sender is allowed to use the connection identity, but it does not decrypt message bodies.

## Encryption And Injection Safety

Use X25519 for pairwise shared secret derivation and ChaCha20-Poly1305 or XChaCha20-Poly1305 for authenticated encryption. AEAD associated data must bind metadata such as sender id, recipient id, message id, and protocol version. If an attacker modifies ciphertext or routing metadata, decryption must fail.

V1 will also reject malformed events, wrong-recipient envelopes, duplicate nonces within a session, and messages from unexpected senders. Peer public-key verification is manual for v1: the client displays a key fingerprint, and users compare it out of band.

## Event-Driven Server

The server runtime uses Tokio. Each connection task converts WebSocket frames into internal events and sends them to a central router through channels. The router owns connection state and forwards outbound events to peer connection queues.

This design keeps concurrent network IO separate from routing decisions. It also makes the system easier to test because routing behavior can be exercised without real sockets.

## Client Behavior

The CLI client is intentionally small. It accepts a server URL, local client id, and peer id. It connects, announces its public key, waits for the peer key, shows the peer fingerprint, then reads stdin lines and sends encrypted messages. Received ciphertext is decrypted locally before display.

## Testing Strategy

Use TDD for each milestone. `chat-core` gets the heaviest test coverage because protocol and crypto behavior must be reusable and deterministic. Required tests include:

- tampered ciphertext fails to decrypt
- tampered associated metadata fails to decrypt
- wrong peer key fails to decrypt
- duplicate nonce is rejected
- malformed event is rejected
- server routes ciphertext without plaintext access
- CLI/server integration can exchange an encrypted message

## Milestones And Checkpoints

Each milestone ends with a short checkpoint note explaining the decisions made:

1. Workspace scaffold and crate boundaries.
2. Protocol event types and serialization rules.
3. Crypto API and safety invariants.
4. In-memory event router.
5. WebSocket server wrapper around the router.
6. CLI client event loop.
7. End-to-end encrypted exchange test.
8. Documentation pass for architecture and future framework extraction.

Checkpoint notes should answer: why this architecture, why this trait or boundary, what safety property was added, and what remains intentionally out of scope.

## Open Decisions Locked For V1

- Client type: CLI terminal client.
- Chat model: 1:1 only.
- Persistence: none.
- Authentication: connection identity plus manual peer fingerprint verification, not accounts.
- Server role: event relay only, no plaintext and no encryption authority.
