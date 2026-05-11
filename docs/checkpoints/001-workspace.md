# Checkpoint 001: Workspace

## Decision

The project starts as a Rust 2024 Cargo workspace managed by mise. The workspace has three crates: `chat-core`, `chat-server`, and `chat-client`.

## Rationale

The split keeps protocol and crypto reusable while keeping the server and CLI apps thin. `mise` owns the Rust toolchain and task commands so contributors run the same checks locally.

## Safety

Workspace lints forbid unsafe code. No protocol, crypto, server routing, WebSocket, or client behavior exists in this checkpoint.

## Scope

This checkpoint intentionally excludes protocol events, cryptography, server routing, WebSocket logic, and client behavior.
