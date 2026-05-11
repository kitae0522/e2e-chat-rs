use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use serde::Serialize;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::PROTOCOL_VERSION;
use crate::event::EncryptedEnvelope;
use crate::types::{Ciphertext, ClientId, MessageId, NonceBytes, PublicKeyBytes};

const SESSION_KEY_SALT: &[u8] = b"e2e-chat-rs/session-key/v1";

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
            local_id,
            peer_id,
        }
    }

    pub fn encrypt(
        &self,
        message_id: MessageId,
        nonce: NonceBytes,
        plaintext: &[u8],
    ) -> Result<EncryptedEnvelope, CryptoError> {
        let cipher = self.cipher()?;
        let aad = associated_data_for(&self.local_id, &self.peer_id, &message_id)?;
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
            nonce,
            ciphertext: Ciphertext::from_bytes(ciphertext),
        })
    }

    pub fn decrypt(&self, envelope: &EncryptedEnvelope) -> Result<Vec<u8>, CryptoError> {
        if envelope.sender != self.peer_id || envelope.recipient != self.local_id {
            return Err(CryptoError::UnexpectedPeer);
        }

        let cipher = self.cipher()?;
        let aad = associated_data_for(&envelope.sender, &envelope.recipient, &envelope.message_id)?;

        cipher
            .decrypt(
                XNonce::from_slice(envelope.nonce.as_array()),
                Payload {
                    msg: envelope.ciphertext.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, CryptoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(SESSION_KEY_SALT), &self.shared_secret.0);
        let mut key = [0u8; 32];
        hkdf.expand(&self.session_info, &mut key)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key).map_err(|_| CryptoError::InvalidKeyLength)?;
        key.zeroize();

        Ok(cipher)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CryptoError {
    #[error("ciphertext authentication failed")]
    AuthenticationFailed,
    #[error("envelope sender or recipient does not match this session")]
    UnexpectedPeer,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("session key derivation failed")]
    KeyDerivationFailed,
    #[error("invalid AEAD key length")]
    InvalidKeyLength,
    #[error("associated data serialization failed")]
    AssociatedDataSerializationFailed,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct SharedSecretBytes([u8; 32]);

#[derive(Serialize)]
struct AssociatedData<'a> {
    version: u16,
    sender: &'a ClientId,
    recipient: &'a ClientId,
    message_id: &'a MessageId,
}

fn associated_data_for(
    sender: &ClientId,
    recipient: &ClientId,
    message_id: &MessageId,
) -> Result<Vec<u8>, CryptoError> {
    serde_json::to_vec(&AssociatedData {
        version: PROTOCOL_VERSION,
        sender,
        recipient,
        message_id,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Ciphertext, ClientId, MessageId, NonceBytes};

    #[test]
    fn decrypts_message_for_matching_pair() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let alice_session = CryptoSession::new(
            &alice,
            bob.public_key(),
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let bob_session = CryptoSession::new(
            &bob,
            alice.public_key(),
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );
        let message_id = MessageId::new();
        let nonce = NonceBytes::from_array([1; 24]);

        let encrypted = alice_session
            .encrypt(message_id, nonce, b"hello bob")
            .expect("encrypt");
        let decrypted = bob_session.decrypt(&encrypted).expect("decrypt");

        assert_eq!(decrypted, b"hello bob");
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let alice_session = CryptoSession::new(
            &alice,
            bob.public_key(),
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let bob_session = CryptoSession::new(
            &bob,
            alice.public_key(),
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );
        let mut encrypted = alice_session
            .encrypt(MessageId::new(), NonceBytes::from_array([2; 24]), b"hello")
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
        let alice_session = CryptoSession::new(
            &alice,
            bob.public_key(),
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let bob_session = CryptoSession::new(
            &bob,
            alice.public_key(),
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );
        let mut encrypted = alice_session
            .encrypt(MessageId::new(), NonceBytes::from_array([3; 24]), b"hello")
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
        let alice_session = CryptoSession::new(
            &alice,
            bob.public_key(),
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let bob_session_with_wrong_key = CryptoSession::new(
            &bob,
            mallory.public_key(),
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );
        let encrypted = alice_session
            .encrypt(MessageId::new(), NonceBytes::from_array([4; 24]), b"hello")
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
        let alice_session = CryptoSession::new(
            &alice,
            bob.public_key(),
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let bob_session = CryptoSession::new(
            &bob,
            alice.public_key(),
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );
        let mut encrypted = alice_session
            .encrypt(MessageId::new(), NonceBytes::from_array([5; 24]), b"hello")
            .expect("encrypt");

        encrypted.sender = ClientId::parse("mallory").expect("mallory");

        assert_eq!(
            bob_session.decrypt(&encrypted),
            Err(CryptoError::UnexpectedPeer)
        );
    }
}
