# Repository Guidelines

## Project Structure & Module Organization

This repository is currently in setup/design phase. The planned Rust workspace keeps production crates under `crates/`: `crates/chat-core` for protocol and crypto, `crates/chat-server` for the event-driven relay, and `crates/chat-client` for the tiny CLI client. Put integration tests in `tests/`, reusable docs in `docs/`, and decision notes in `docs/checkpoints/`.

## Build, Test, and Development Commands

Use `mise` for the Rust toolchain and project tasks. After `mise.toml` is added, use:

- `mise install`: install the pinned Rust toolchain and components.
- `mise run check`: type-check the workspace.
- `mise run test`: run unit and integration tests.
- `mise run fmt-fix`: format Rust code.
- `mise run verify`: run format, check, clippy, and tests.

Avoid adding Docker, databases, or service dependencies until the E2EE relay needs them.

## Coding Style & Naming Conventions

Use Rust 2024 style via `rustfmt`. Use four-space indentation, `snake_case` for functions/modules/files, `PascalCase` for types and traits, and `SCREAMING_SNAKE_CASE` for constants. Prefer newtypes for protocol-sensitive values such as `ClientId`, `MessageId`, `Nonce`, and `Ciphertext`. Add traits only for real boundaries, not speculative abstraction.

## Testing Guidelines

Use TDD for feature work. Place unit tests next to code in `#[cfg(test)] mod tests`, and put cross-crate behavior in `tests/*.rs`. Name tests by behavior, such as `rejects_tampered_ciphertext` or `routes_ciphertext_without_plaintext_access`. Run `mise run verify` before opening a pull request.

## Commit & Pull Request Guidelines

No commit history is available in this checkout, so use concise imperative commit subjects, preferably Conventional Commit style such as `feat: add websocket handshake` or `fix: handle closed peer stream`. Pull requests should include a short summary, testing evidence, linked issues when available, and screenshots or logs for user-visible behavior.

## Security & Configuration Tips

Do not commit secrets, tokens, local certificates, or generated private keys. Keep environment-specific settings in ignored `.env` files and document required variables in `.env.example` once configuration is introduced.
