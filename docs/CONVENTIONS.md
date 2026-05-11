# Project Conventions

This document is the shared rulebook for contributors and AI agents working in this repository.

## Communication Language

- CLI conversation with the project owner: English.
- Public GitHub issues and pull requests: Korean.
- GitHub issue overview sections may use natural Korean sentences.
- GitHub task lists, acceptance criteria, and notes should use noun-style or short simple Korean.

## Branch Naming

Use this format:

```text
<type>/<issue-number>/<title>
```

Examples:

```text
feature/1/workspace-setup
chore/1/git-hooks-setup
fix/12/nonce-validation
```

Rules:

- Branch type is lowercase.
- Title is lowercase and hyphenated.
- Title should describe the concrete scope.

## Commit Messages

Commit subject types must be uppercase.

Allowed types:

```text
FEAT, FIX, CHORE, DOCS, TEST, REFACTOR, STYLE, PERF, BUILD, CI, REVERT
```

Required format:

```text
CHORE: Git hooks 설정

- 어떤 작업을 했는가: Git hooks 설정
- 어떤 이슈인가: #1 저장소 작업 규칙 정리
- 그래서 무엇을 했는가: commit-msg와 pre-commit hook 추가
```

Rules:

- Subject starts with an uppercase type.
- Body includes all three Korean fields.
- Body should explain the reason and concrete result, not just repeat the subject.

## GitHub Issues

Create an issue before coding or planning a milestone.

Use the repository issue templates. Write public issue content in Korean.

Issue style:

- Overview: natural Korean sentences.
- Tasks: noun-style or short simple Korean.
- Acceptance criteria: noun-style or short simple Korean.
- Notes: short simple Korean.

Example task text:

```markdown
- [ ] mise 기반 Rust 2024 워크스페이스 설정
- [ ] 프로토콜 이벤트와 newtype 구현
- [ ] ciphertext 변조 거부 테스트
```

## Pull Requests

Create a pull request after finishing a milestone or feature.

Rules:

- Use the repository PR template.
- Write PR content in Korean.
- Link the related issue with `Closes #N` when the PR completes that scope.
- Include local verification results.
- Keep each PR scoped to one milestone or one feature.

PR checklist sections should use noun-style or short simple Korean.

## Merge Policy

Use rebase and fast-forward merge only.

Rules:

- Do not create merge commits.
- Rebase the feature branch onto `main` before merge when needed.
- Keep `main` linear.

## Git Hooks

The repository uses `.githooks/` through:

```bash
git config core.hooksPath .githooks
```

Current hooks:

- `commit-msg`: enforces uppercase commit type and required Korean body fields.
- `pre-commit`: runs `mise run fmt` when `mise.toml` exists.

If hooks do not run locally, configure the hooks path again.

## Development Flow

Default flow:

1. Create or confirm the GitHub issue.
2. Create a clear branch from `main`.
3. Work by milestone.
4. Use TDD for implementation work.
5. Add or update checkpoint docs after each milestone.
6. Run local verification.
7. Commit with the required message format.
8. Push the branch.
9. Open a Korean PR with the repository template.
