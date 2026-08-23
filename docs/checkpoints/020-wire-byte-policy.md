# Checkpoint 020: Wire Byte Field Serialization Policy

## Decision

`PublicKeyBytes`, `NonceBytes`, and `Ciphertext` serialize as standard-alphabet base64 strings instead of JSON number arrays, via manual `Serialize`/`Deserialize` impls in `chat-core::types`. Decoding rejects invalid base64 and wrong decoded lengths. The registered-but-unused `base64` dependency is now the single encoding implementation.

## Rationale

Measured overhead of JSON number arrays: a 32-byte public key encoded to 96 characters vs 46 with base64 (~52% larger); an 80-byte ciphertext 240 vs 110 (~54% larger). Every envelope carries a key, nonce, and ciphertext, so the relayed event size roughly halves.

Alternatives considered:

- **Protobuf/binary transport** — largest win but a full transport migration; recorded as future work in `docs/ARCHITECTURE.md`, not attempted now.
- **`ProtocolCodec` trait abstraction** — only one codec exists; adding the boundary before a second real codec would be speculative.

JSON stays for debuggability; base64 keeps byte fields compact and length-validated at decode time (public key must be exactly 32 bytes, nonce exactly 24).

## Wire Format Migration

Breaking change: these fields move from JSON arrays (`[7, 7, ...]`) to base64 strings (`"BwcHBw..."`). Accepted because v1 is unreleased with no deployed clients, consistent with checkpoint 016. Future transport changes (binary frames) must be documented the same way when attempted.

## Validation

- `cargo test -p chat-core serializes_public_key_as_base64_string`
- `cargo test -p chat-core roundtrips_ciphertext_through_base64`
- `cargo test -p chat-server --test ws_relay` (full E2EE flow over real sockets)
- `mise run verify`
