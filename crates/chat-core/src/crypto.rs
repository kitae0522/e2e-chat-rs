use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::PROTOCOL_VERSION;
use crate::event::EncryptedEnvelope;
use crate::nonce::NonceTracker;
use crate::types::{Ciphertext, ClientId, MessageId, NonceBytes, PublicKeyBytes};

const SESSION_KEY_SALT: &[u8] = b"e2e-chat-rs/session-key/v1";

/// Deterministic fingerprint of a peer public key for out-of-band comparison.
///
/// SHA-256 over the raw key bytes, lowercase hex. Users compare this string
/// through a separate channel to detect man-in-the-middle key substitution.
pub fn fingerprint(public_key: &PublicKeyBytes) -> String {
    let digest = Sha256::digest(public_key.as_array());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

pub struct KeyPair {
    secret: StaticSecret,
    public_key: PublicKeyBytes,
}

impl KeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);

        Self {
            secret,
            public_key: PublicKeyBytes::from_array(public_key.to_bytes()),
        }
    }

    pub fn public_key(&self) -> PublicKeyBytes {
        self.public_key
    }
}

pub struct CryptoSession {
    shared_secret: SharedSecretBytes,
    session_info: Vec<u8>,
    local_id: ClientId,
    peer_id: ClientId,
    inbound_nonces: HashMap<u32, NonceTracker>,
    outbound_nonce_prefix: [u8; 16],
    next_outbound_nonce: u64,
    /// Session key generation for outbound encryption.
    epoch: u32,
}

impl CryptoSession {
    pub fn new(
        local_keypair: &KeyPair,
        peer_public_key: PublicKeyBytes,
        local_id: ClientId,
        peer_id: ClientId,
    ) -> Self {
        let peer_public_key = PublicKey::from(*peer_public_key.as_array());
        let shared_secret = local_keypair.secret.diffie_hellman(&peer_public_key);
        let session_info = session_info(&local_id, &peer_id);

        Self {
            shared_secret: SharedSecretBytes(*shared_secret.as_bytes()),
            session_info,
            outbound_nonce_prefix: nonce_prefix(&local_id, &peer_id),
            local_id,
            peer_id,
            inbound_nonces: HashMap::new(),
            next_outbound_nonce: 0,
            epoch: 0,
        }
    }

    /// Current session key generation for outbound encryption.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    #[cfg(test)]
    pub(crate) fn bump_epoch_for_test(&mut self) {
        self.epoch += 1;
        // 전환기 수신자는 현재 + 바로 이전 epoch만 추적한다.
        self.inbound_nonces
            .retain(|generation, _| *generation + 1 >= self.epoch);
    }

    pub fn encrypt(
        &mut self,
        message_id: MessageId,
        plaintext: &[u8],
    ) -> Result<EncryptedEnvelope, CryptoError> {
        let cipher = self.cipher_for(self.epoch)?;
        let nonce = self.next_nonce()?;
        let aad = associated_data_for(&self.local_id, &self.peer_id, &message_id, self.epoch)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(nonce.as_array()),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(EncryptedEnvelope {
            sender: self.local_id.clone(),
            recipient: self.peer_id.clone(),
            message_id,
            epoch: self.epoch,
            nonce,
            ciphertext: Ciphertext::from_bytes(ciphertext),
        })
    }

    pub fn decrypt(&mut self, envelope: &EncryptedEnvelope) -> Result<Vec<u8>, CryptoError> {
        if envelope.sender != self.peer_id || envelope.recipient != self.local_id {
            return Err(CryptoError::UnexpectedPeer);
        }

        // 전환기 동안 현재와 바로 이전 epoch만 수용한다.
        let is_current = envelope.epoch == self.epoch;
        let is_previous = self.epoch > 0 && envelope.epoch + 1 == self.epoch;
        if !is_current && !is_previous {
            return Err(CryptoError::UnknownEpoch);
        }

        let cipher = self.cipher_for(envelope.epoch)?;
        let aad = associated_data_for(
            &envelope.sender,
            &envelope.recipient,
            &envelope.message_id,
            envelope.epoch,
        )?;

        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(envelope.nonce.as_array()),
                Payload {
                    msg: envelope.ciphertext.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        self.inbound_nonces
            .entry(envelope.epoch)
            .or_default()
            .mark_seen(envelope.nonce)
            .map_err(|_| CryptoError::DuplicateNonce)?;
        Ok(plaintext)
    }

    fn cipher_for(&self, epoch: u32) -> Result<XChaCha20Poly1305, CryptoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(SESSION_KEY_SALT), &self.shared_secret.0);
        let mut info = self.session_info.clone();
        info.extend_from_slice(&epoch.to_be_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(&info, &mut key)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key).map_err(|_| CryptoError::InvalidKeyLength)?;
        key.zeroize();

        Ok(cipher)
    }

    fn next_nonce(&mut self) -> Result<NonceBytes, CryptoError> {
        self.next_outbound_nonce = self
            .next_outbound_nonce
            .checked_add(1)
            .ok_or(CryptoError::NonceExhausted)?;

        let mut nonce = [0u8; 24];
        nonce[..16].copy_from_slice(&self.outbound_nonce_prefix);
        nonce[16..].copy_from_slice(&self.next_outbound_nonce.to_be_bytes());
        Ok(NonceBytes::from_array(nonce))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CryptoError {
    #[error("ciphertext authentication failed")]
    AuthenticationFailed,
    #[error("envelope sender or recipient does not match this session")]
    UnexpectedPeer,
    #[error("envelope epoch is neither the current nor the previous session generation")]
    UnknownEpoch,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("session key derivation failed")]
    KeyDerivationFailed,
    #[error("invalid AEAD key length")]
    InvalidKeyLength,
    #[error("associated data serialization failed")]
    AssociatedDataSerializationFailed,
    #[error("nonce counter exhausted")]
    NonceExhausted,
    #[error("nonce was already used in this session")]
    DuplicateNonce,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SharedSecretBytes([u8; 32]);

#[derive(Serialize)]
struct AssociatedData<'a> {
    version: u16,
    sender: &'a ClientId,
    recipient: &'a ClientId,
    message_id: &'a MessageId,
    epoch: u32,
}

fn associated_data_for(
    sender: &ClientId,
    recipient: &ClientId,
    message_id: &MessageId,
    epoch: u32,
) -> Result<Vec<u8>, CryptoError> {
    serde_json::to_vec(&AssociatedData {
        version: PROTOCOL_VERSION,
        sender,
        recipient,
        message_id,
        epoch,
    })
    .map_err(|_| CryptoError::AssociatedDataSerializationFailed)
}

fn session_info(local_id: &ClientId, peer_id: &ClientId) -> Vec<u8> {
    let mut ids = [local_id.as_str(), peer_id.as_str()];
    ids.sort_unstable();

    let mut info = Vec::from("e2e-chat-rs/x25519-xchacha20poly1305/v1");
    info.push(0);
    info.extend_from_slice(ids[0].as_bytes());
    info.push(0);
    info.extend_from_slice(ids[1].as_bytes());
    info
}

fn nonce_prefix(local_id: &ClientId, peer_id: &ClientId) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"e2e-chat-rs/xchacha20poly1305-nonce/v1");
    hasher.update(&[0]);
    hasher.update(local_id.as_str().as_bytes());
    hasher.update(&[0]);
    hasher.update(peer_id.as_str().as_bytes());

    let hash = hasher.finalize();
    let mut prefix = [0u8; 16];
    prefix.copy_from_slice(&hash.as_bytes()[..16]);
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Ciphertext, ClientId, MessageId, PublicKeyBytes};

    #[test]
    fn fingerprints_public_key_deterministically() {
        // 지문은 대역 비교의 기준이므로 결정적이어야 한다.
        let key = PublicKeyBytes::from_array([7; 32]);

        let first = fingerprint(&key);
        let second = fingerprint(&key);

        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(
            first
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(first, fingerprint(&PublicKeyBytes::from_array([8; 32])));
    }

    #[test]
    fn binds_epoch_into_associated_data() {
        // epoch는 AAD에 바인딩된다: 이전 epoch 메시지의 epoch 필드를 바꾸면
        // 해당 epoch 키로 복호화가 실패해야 한다.
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let mut alice_session = test_session(&alice, &bob, "alice", "bob");
        let mut bob_session = test_session(&bob, &alice, "bob", "alice");
        let envelope = alice_session
            .encrypt(MessageId::new(), b"hi")
            .expect("encrypt");
        assert_eq!(envelope.epoch, 0);

        // 양쪽 모두 재키 전환으로 epoch를 올린다.
        alice_session.bump_epoch_for_test();
        bob_session.bump_epoch_for_test();

        bob_session
            .decrypt(&envelope)
            .expect("accept previous epoch");

        let mut tampered = envelope.clone();
        tampered.epoch += 1;
        assert_eq!(
            bob_session.decrypt(&tampered),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn accepts_previous_epoch_only_during_transition() {
        // 전환기 수신자는 현재 + 바로 이전 epoch만 수용한다.
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let mut alice_session = test_session(&alice, &bob, "alice", "bob");
        let mut bob_session = test_session(&bob, &alice, "bob", "alice");
        let old_envelope = alice_session
            .encrypt(MessageId::new(), b"old")
            .expect("encrypt old epoch");

        // 양쪽 모두 epoch를 올린 뒤 새 epoch 메시지를 만든다.
        alice_session.bump_epoch_for_test();
        bob_session.bump_epoch_for_test();
        let new_envelope = alice_session
            .encrypt(MessageId::new(), b"new")
            .expect("encrypt new epoch");

        assert_eq!(new_envelope.epoch, old_envelope.epoch + 1);
        bob_session
            .decrypt(&new_envelope)
            .expect("accept new epoch");
        bob_session
            .decrypt(&old_envelope)
            .expect("accept previous epoch");

        let mut future = new_envelope.clone();
        future.epoch += 2;
        assert_eq!(bob_session.decrypt(&future), Err(CryptoError::UnknownEpoch));
    }

    fn test_session(
        local: &KeyPair,
        peer: &KeyPair,
        local_id: &str,
        peer_id: &str,
    ) -> CryptoSession {
        CryptoSession::new(
            local,
            peer.public_key(),
            ClientId::parse(local_id).expect("local id"),
            ClientId::parse(peer_id).expect("peer id"),
        )
    }

    #[test]
    fn decrypts_message_for_matching_pair() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let mut alice_session = CryptoSession::new(
            &alice,
            bob.public_key(),
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let mut bob_session = CryptoSession::new(
            &bob,
            alice.public_key(),
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );
        let message_id = MessageId::new();

        let encrypted = alice_session
            .encrypt(message_id, b"hello bob")
            .expect("encrypt");
        let decrypted = bob_session.decrypt(&encrypted).expect("decrypt");

        assert_eq!(decrypted, b"hello bob");
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let mut alice_session = CryptoSession::new(
            &alice,
            bob.public_key(),
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let mut bob_session = CryptoSession::new(
            &bob,
            alice.public_key(),
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );
        let mut encrypted = alice_session
            .encrypt(MessageId::new(), b"hello")
            .expect("encrypt");

        encrypted.ciphertext =
            Ciphertext::from_bytes(vec![0; encrypted.ciphertext.as_bytes().len()]);

        assert_eq!(
            bob_session.decrypt(&encrypted),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn rejects_tampered_message_id() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let mut alice_session = CryptoSession::new(
            &alice,
            bob.public_key(),
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let mut bob_session = CryptoSession::new(
            &bob,
            alice.public_key(),
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );
        let mut encrypted = alice_session
            .encrypt(MessageId::new(), b"hello")
            .expect("encrypt");

        encrypted.message_id = MessageId::new();

        assert_eq!(
            bob_session.decrypt(&encrypted),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn rejects_wrong_peer_key() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let mallory = KeyPair::generate();
        let mut alice_session = CryptoSession::new(
            &alice,
            bob.public_key(),
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let mut bob_session_with_wrong_key = CryptoSession::new(
            &bob,
            mallory.public_key(),
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );
        let encrypted = alice_session
            .encrypt(MessageId::new(), b"hello")
            .expect("encrypt");

        assert_eq!(
            bob_session_with_wrong_key.decrypt(&encrypted),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn rejects_tampered_metadata() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let mut alice_session = CryptoSession::new(
            &alice,
            bob.public_key(),
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let mut bob_session = CryptoSession::new(
            &bob,
            alice.public_key(),
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );
        let mut encrypted = alice_session
            .encrypt(MessageId::new(), b"hello")
            .expect("encrypt");

        encrypted.sender = ClientId::parse("mallory").expect("mallory");

        assert_eq!(
            bob_session.decrypt(&encrypted),
            Err(CryptoError::UnexpectedPeer)
        );
    }

    #[test]
    fn rejects_replayed_inbound_nonce() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let mut alice_session = CryptoSession::new(
            &alice,
            bob.public_key(),
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let mut bob_session = CryptoSession::new(
            &bob,
            alice.public_key(),
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );
        let encrypted = alice_session
            .encrypt(MessageId::new(), b"hello")
            .expect("encrypt");

        bob_session.decrypt(&encrypted).expect("first decrypt");

        assert_eq!(
            bob_session.decrypt(&encrypted),
            Err(CryptoError::DuplicateNonce)
        );
    }

    #[test]
    fn generates_distinct_nonces_for_each_direction() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let mut alice_session = CryptoSession::new(
            &alice,
            bob.public_key(),
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let mut bob_session = CryptoSession::new(
            &bob,
            alice.public_key(),
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );

        let from_alice = alice_session
            .encrypt(MessageId::new(), b"hello bob")
            .expect("encrypt alice");
        let from_bob = bob_session
            .encrypt(MessageId::new(), b"hello alice")
            .expect("encrypt bob");

        assert_ne!(from_alice.nonce, from_bob.nonce);
    }
}
