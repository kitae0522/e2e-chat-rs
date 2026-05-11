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

See [docs/CONVENTIONS.md](docs/CONVENTIONS.md) for the full contributor and AI-agent workflow.

Use clear branch names: `<type>/<issue-number>/<title>`, for example `feature/1/workspace-setup` or `fix/12/nonce-validation`. Keep the branch type lowercase, and keep the title short, lowercase, and hyphenated.

Commit subject types must be uppercase, for example `CHORE: Rust 워크스페이스 설정` or `FEAT: 암호화 세션 추가`. Commit messages must be easy to read and include this structure in the body:

- `어떤 작업을 했는가`: the work category or scope.
- `어떤 이슈인가`: the related issue or problem.
- `그래서 무엇을 했는가`: the concrete change.

Example:

```text
CHORE: Rust 워크스페이스 설정

- 어떤 작업을 했는가: Rust 프로젝트 초기 설정
- 어떤 이슈인가: #1 E2E 채팅 v1 구현 준비
- 그래서 무엇을 했는가: mise, Cargo workspace, 기본 크레이트 구조 추가
```

Pull requests must use the repository PR template and be written in Korean. Merge PRs with rebase and fast-forward only; avoid merge commits.

## Security & Configuration Tips

Do not commit secrets, tokens, local certificates, or generated private keys. Keep environment-specific settings in ignored `.env` files and document required variables in `.env.example` once configuration is introduced.
