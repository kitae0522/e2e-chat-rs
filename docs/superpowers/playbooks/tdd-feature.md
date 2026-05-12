# Playbook: TDD Feature Implementation

Standard TDD procedure for implementing a new feature.

Do not commit the failing-test red state in this repository.
Confirm the failure, then make the minimal implementation green and commit only buildable units.

## Prerequisites

- [ ] GitHub issue exists
- [ ] Acceptance criteria are written in the issue
- [ ] Required traits/types already exist or are defined in this issue

## Steps

### Step 1 — Design the interface without code
Before implementation, state:
```
Assumptions: <what this feature depends on>
Success criteria: <what completion means>
Test list: <test names and what each verifies>
```
Ask before implementing if anything is unclear.

### Step 2 — Write the failing test first
```rust
#[cfg(test)]
mod tests {
    // Test names should describe behavior: rejects_tampered_ciphertext
    // The test should encode WHY the behavior matters
    // Compile errors are acceptable when the required type does not exist yet
    #[test]
    fn <behavior_name>() {
        // Arrange
        // Act
        // Assert: this should fail if the business behavior changes
    }
}
```
Verification: confirm the test fails for the intended reason.
Do not commit: red state conflicts with the repository's buildable-commit rule.

### Step 3 — Minimal implementation
Write only the code needed to pass the test.
Do not add speculative abstractions or future-facing design.

Commit: `FEAT: <feature name>`
Scope: include both the failing test and the minimal implementation.

### Step 4 — Refactor if needed
Refactor only while tests are passing.
Test results must be the same before and after refactoring.

Commit: `REFACTOR: <feature cleanup>`

### Step 5 — Verification
```bash
mise run verify
```

## Done Criteria

- [ ] All acceptance criteria are met
- [ ] `mise run verify` passes
- [ ] Tests verify behavior, not just the presence of a return value
- [ ] No `unwrap()`/`expect()` in non-test code unless justified by a comment
- [ ] Red failure and green transition are recorded in the work log or PR description
