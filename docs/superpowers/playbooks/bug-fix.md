# Playbook: Bug Fix

Standard procedure for reproducing and fixing a bug.

Do not commit the failing-test red state in this repository.
Confirm the reproduction failure, then make the minimal fix green and commit only buildable units.

## Steps

### Step 1 — Write the reproduction test first
```rust
#[test]
fn <bug_description>_is_rejected() {
    // This test should fail while the bug exists
    // This test should pass after the fix
}
```
Verification: confirm the test fails for the intended reason while the bug exists.
Do not commit: red state conflicts with the repository's buildable-commit rule.

### Step 2 — Minimal fix
Change only the code that causes the bug.
Do not change adjacent code or style.

Commit: `FIX: <bug description>`
Scope: include both the reproduction test and the minimal fix.

### Step 3 — Verification
```bash
mise run verify
```

## Done Criteria

- [ ] Reproduction test fails before the fix and passes after the fix
- [ ] `mise run verify` passes
- [ ] Fix scope is limited to the bug cause
- [ ] Red failure and green transition are recorded in the work log or PR description
