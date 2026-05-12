# Repository Guidelines

## Project Identity

`e2e-chat-rs` is a Rust workspace implementing a 1:1 E2EE chat relay.
Long-term goal: become a reusable framework crate for E2EE services.

```
crates/
  chat-core/    # protocol, crypto, trait definitions
  chat-server/  # axum + tokio WebSocket relay
  chat-client/  # CLI adapter
docs/
  checkpoints/  # milestone decision records
  superpowers/  # plans and specs for Codex agents
```

Checkpoint docs are for milestone decisions or architecture, security, protocol, and workflow boundaries. Do not add a checkpoint for routine documentation edits or small localized fixes.

## Toolchain

Use `mise` for the Rust toolchain and project tasks. After `mise.toml` is added, use:

```bash
mise install                    # install pinned Rust toolchain
mise run check                  # type-check workspace
mise run test                   # run all tests
mise run fmt-fix                # format code
mise run verify                 # fmt + check + clippy + test (run before every PR)
```

Always run `mise run verify` before marking a task done.
If `mise` is unavailable, fall back to `cargo check && cargo test`.

## Behavioral Rules

### Rule 1 — Think Before Coding
State assumptions explicitly before writing any code.
If a simpler approach exists, say so before implementing the complex one.
Ask when ambiguous. Do not guess silently.
If you encounter a design decision not covered by this file, stop and ask.

### Rule 2 — Simplicity First
Write the minimum code that solves the problem.
No speculative features, no abstractions for single-use code.
Test: would a senior Rust engineer say this is overcomplicated? If yes, simplify.

### Rule 3 — Surgical Changes
Touch only what the issue requires.
Do not improve adjacent code, fix unrelated style, or refactor what isn't broken.
Do not add features beyond the issue scope.
Match existing code style exactly.

### Rule 4 — Read Before You Write
Before adding code to an existing file, read:
- The file's public API and type signatures
- The immediate caller of the code you are changing
- Any shared types in `chat-core` that the code depends on
  If you do not understand why existing code is structured a certain way, say so.
  "Looks orthogonal to me" is not sufficient justification for not reading it.

### Rule 5 — Surface Conflicts, Don't Average Them
If two patterns in the codebase contradict (e.g. two error handling styles),
pick the more recent or more tested one, explain why, and flag the other for cleanup.
Do not write code that blends both patterns.
Averaging conflicting patterns produces the worst code.

### Rule 6 — Tests Verify Intent
Write failing tests before writing implementation (TDD).
Every test must encode WHY the behavior matters, not just WHAT it returns.
Name tests by behavior: `rejects_tampered_ciphertext`, not `test_encrypt`.
A test that cannot fail when business logic changes is wrong.

### Rule 7 — Commit Granularity
Make a separate commit after each meaningful step.
Each commit must leave the workspace in a buildable, test-passing state.
Do not batch all changes into a single commit at the end.
Commit format: see Commit Convention section below.

### Rule 8 — Fail Loud
Do not say "done" if anything was skipped, broken, or unverified.
If a test was skipped, say why.
If `mise run verify` was not run, say so.
Surface uncertainty in the PR description rather than hiding it.

## Policy: Security

Do not commit secrets, tokens, private keys, or certificates.
Do not introduce `unwrap()` or `expect()` in non-test code without a comment explaining why a panic is acceptable.
Zeroize all key material. If adding a new key type, implement `ZeroizeOnDrop`.
AAD must bind: version + sender + recipient + message_id.
Do not change the wire format (`WireEvent`, `EncryptedEnvelope`) without a documented migration path.

## Policy: Error Handling

Use typed error enums, not `anyhow` in library code (`chat-core`).
`anyhow` is acceptable in binary crates (`chat-server`, `chat-client`) for operational errors.
Every error variant must have a distinct name that describes the failure reason.
Do not use `String` as an error type.

## Out of Scope (do not do without explicit instruction)

- Do not add Docker, databases, or external service dependencies
- Do not introduce `async-trait` unless the trait is already async in the codebase
- Do not change `Cargo.toml` dependency versions without asking
- Do not add new crates to the workspace without asking
- Do not rename public types in `chat-core` without asking (breaking change)

## Coding Style & Naming Conventions

Use Rust 2024 style via `rustfmt`. Use four-space indentation, `snake_case` for functions/modules/files, `PascalCase` for types and traits, and `SCREAMING_SNAKE_CASE` for constants. Prefer newtypes for protocol-sensitive values such as `ClientId`, `MessageId`, `Nonce`, and `Ciphertext`. Add traits only for real boundaries, not speculative abstraction.

## Testing Guidelines

Use TDD for feature work. Place unit tests next to code in `#[cfg(test)] mod tests`, and put cross-crate behavior in `tests/*.rs`. Name tests by behavior, such as `rejects_tampered_ciphertext` or `routes_ciphertext_without_plaintext_access`. Run `mise run verify` before opening a pull request.

## Commit & Pull Request Guidelines

See [docs/CONVENTIONS.md](docs/CONVENTIONS.md) for the full contributor and AI-agent workflow.

Use clear branch names: `<type>/<issue-number>/<title>`, for example `feature/1/workspace-setup` or `fix/12/nonce-validation`. Keep the branch type lowercase, and keep the title short, lowercase, and hyphenated.

Commit subject types must be uppercase, for example `CHORE: Configure Rust workspace` or `FEAT: Add crypto session`. Commit messages must be easy to read and include these exact Korean field labels in the body:

- `어떤 작업을 했는가`: work category or scope.
- `어떤 이슈인가`: related issue or problem.
- `그래서 무엇을 했는가`: concrete change.

Example:

```text
CHORE: Configure Rust workspace

- 어떤 작업을 했는가: Rust project setup
- 어떤 이슈인가: #1 Prepare E2E chat v1 implementation
- 그래서 무엇을 했는가: Add mise, Cargo workspace, and base crate structure
```

Pull requests must use the repository PR template and be written in Korean. Merge PRs with rebase and fast-forward only; avoid merge commits.

## Security & Configuration Tips

Do not commit secrets, tokens, local certificates, or generated private keys. Keep environment-specific settings in ignored `.env` files and document required variables in `.env.example` once configuration is introduced.
