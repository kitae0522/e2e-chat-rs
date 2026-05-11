# Checkpoint 009: Runbook and Architecture Docs

## Decision

The repository now has a README quick start and architecture notes for the current end-to-end chat flow.

## Rationale

The code is usable enough to run locally, so the next checkpoint documents how to operate it and why the crate boundaries exist.

This helps contributors and AI agents avoid mixing concerns:

- crypto and protocol logic in `chat-core`
- relay routing in `chat-server`
- terminal and WebSocket adapter logic in `chat-client`

## Validation

- `mise run verify`

## Scope

This checkpoint intentionally excludes new runtime behavior.
