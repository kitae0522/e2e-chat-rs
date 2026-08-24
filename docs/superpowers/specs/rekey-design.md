# Rekey Protocol Design (v2 Proposal)

Status: **proposal — not implemented**
Related: checkpoint 013 (peer key idempotency), checkpoint 017 (fingerprint pinning), issue on file

## Motivation

Today a `CryptoSession` is built once from the X25519 shared secret and never
changes. Consequences:

1. If a peer legitimately rotates its long-term key (new device, reinstall),
   the client rejects every subsequent `PeerKey` forever — there is no recovery
   path (checkpoint 013).
2. The entire conversation history is protected by one key derived from one
   ECDH. Compromise of that single secret exposes all past and future traffic
   within the session.

A rekey flow fixes both: it provides an authenticated recovery path and rolls
the session key forward.

## Goals / Non-Goals

Goals:
- Both peers can advance to a fresh session key without dropping the connection.
- A legitimate long-term key change can be accepted through an explicit,
  user-visible flow.
- Rekey control messages cannot be forged by a network attacker.

Non-goals (v2 scope):
- Full double-ratchet / per-message forward secrecy.
- Post-compromise security guarantees beyond "new key is independent of old".
- Group chat key management (still 1:1 only).
- Automatic trust-on-key-change without user confirmation.

## Threat Model Assumptions

- The relay sees only ciphertext and routing metadata (unchanged).
- A network attacker can replay, drop, reorder, and inject relay events.
- An attacker who does not hold the current session key cannot forge rekey
  control messages (they are AEAD-protected — see below).
- Key substitution by a MITM at first contact is handled by fingerprint
  pinning (checkpoint 017), not by this protocol.

## Protocol

### Principle: control messages ride inside the session

Rekey handshakes are **encrypted payloads inside the existing session**, not
plaintext control events. Only holders of the current session key can produce
or read them, so the handshake inherits the session's authentication. The
relay treats them as opaque ciphertext exactly like chat messages.

### Events

Two new variants in `EncryptedEnvelope`'s inner payload type (a small enum
replacing raw UTF-8 plaintext):

```text
SessionPayload::Chat(String)
SessionPayload::RekeyRequest { rekey_id: [u8;16], ephemeral_public_key: PublicKeyBytes }
SessionPayload::RekeyResponse { rekey_id: [u8;16], ephemeral_public_key: PublicKeyBytes }
```

The outer `WireEvent::EncryptedMessage` shape is unchanged — the relay needs
no new routing rules.

### Flow

```text
Initiator                                Responder
---------                                ---------
generate ephemeral pair Ei
send RekeyRequest{rid, Epi}       --->   decrypt under current key
                                         generate ephemeral pair Er
                                         derive new key (below)
                                         send RekeyResponse{rid, Epr}
                                         (still encrypting at old epoch)
                  <---                   switch outbound to new epoch
decrypt response under current key
derive new key
switch outbound to new epoch
```

- The responder sends `RekeyResponse` **before** switching its outbound epoch,
  so the response travels under the epoch the initiator can still read. Both
  sides then switch, and dual-epoch reception covers the brief skew.
- `rekey_id` (128-bit random) correlates request/response and prevents
  replaying an old response into a new handshake.
- Each side switches its **outbound** key as soon as its own role completes;
  both keep accepting inbound on the previous epoch until they see the first
  message of the new epoch (see In-flight Handling).

### Key derivation chain

```text
new_shared     = X25519(Ei_priv, Epr_pub)          // fresh ephemeral DH
master_secret' = HKDF-Extract(salt = master_secret,  // chained to old key
                              IKM  = new_shared)
session_key'   = HKDF-Expand(master_secret', session_info ++ epoch)
```

- Chaining through `HKDF-Extract(salt=old master)` means an attacker must know
  the *current* master secret to derive any future key — matching the
  authentication property of the handshake carrier.
- `epoch` (monotonic counter starting at 0) enters the HKDF `info`, so keys are
  domain-separated per generation.

### Epochs and wire format change

`EncryptedEnvelope` gains `epoch: u32`, bound into the AAD alongside version,
sender, recipient, message id. This is a breaking wire change; migration
follows the checkpoint 016/020 precedent (v1 unreleased).

### In-flight handling

Receiver keeps the two most recent epochs (current + previous). Decryption
tries current first, then previous. When a message arrives with an epoch newer
than any known, it activates that epoch and drops the older one. This gives
at-most-one-generation slack without timers or acknowledgments.

### Long-term key rotation (recovery path)

If a peer's long-term key changes, the pinned fingerprint no longer matches
and the session is dead. The recovery UX is explicit:

1. Client detects changed `PeerKey` for an established peer id.
2. UI prints the new fingerprint and asks the user to confirm out-of-band
   comparison (same manual model as initial verification).
3. On confirmation, the client discards the old session and performs a fresh
   handshake (new `CryptoSession`) with the new key — not a silent swap.

## State Machine (per session)

```text
Established --send RekeyRequest--> InitiatorWaiting
Established <--recv RekeyRequest--  ResponderSwitched
InitiatorWaiting <--recv RekeyResponse-- Established(epoch+1)
ResponderSwitched --first msg at epoch+1 received--> Established(epoch+1)
```

Any decryption failure during a handshake, unknown `rekey_id`, or duplicate
response aborts the handshake and keeps the old epoch.

## Implementation Plan (if approved)

1. `chat-core`: `SessionPayload` enum + epoch in envelope + dual-epoch decrypt
   (TDD: roundtrip, cross-epoch ordering, replay/forgery rejection).
2. `chat-core`: rekey derivation chain + state machine in `CryptoSession`.
3. `chat-client`: `/rekey` command, key-change confirmation prompt, status
   display including epoch.
4. Docs: checkpoint + ARCHITECTURE safety-check updates.

## Open Questions

1. Should rekey also be triggered automatically (e.g., every N messages)?
   Proposal: manual-only (`/rekey`) for v2; automatic triggers later.
2. Does the relay need awareness of epochs for outbox ordering? Proposal: no —
   epochs are end-to-end; relay stays oblivious.
3. Backward-compatible rollout with mixed versions? Proposal: none — same
   unreleased-v1 precedent as checkpoints 016/020.
