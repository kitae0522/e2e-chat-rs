use chat_core::crypto::{CryptoError, CryptoSession, KeyPair, fingerprint};
use chat_core::event::WireEvent;
use chat_core::types::{ClientId, MessageId, PublicKeyBytes};

pub struct ClientSession {
    local_id: ClientId,
    peer_id: ClientId,
    keypair: KeyPair,
    peer_public_key: Option<PublicKeyBytes>,
    crypto_session: Option<CryptoSession>,
    expected_peer_fingerprint: Option<String>,
}

impl ClientSession {
    pub fn new(local_id: ClientId, peer_id: ClientId) -> Self {
        Self {
            local_id,
            peer_id,
            keypair: KeyPair::generate(),
            peer_public_key: None,
            crypto_session: None,
            expected_peer_fingerprint: None,
        }
    }

    /// Pins the expected peer fingerprint (hex, case/whitespace tolerant).
    /// Inbound PeerKey events whose fingerprint differs are rejected.
    pub fn expect_peer_fingerprint(&mut self, fingerprint: String) {
        self.expected_peer_fingerprint = Some(fingerprint.trim().to_lowercase());
    }

    /// Fingerprint of the accepted peer key, for out-of-band verification.
    pub fn peer_fingerprint(&self) -> Option<String> {
        self.peer_public_key.as_ref().map(fingerprint)
    }

    pub fn client_hello(&self) -> WireEvent {
        WireEvent::ClientHello {
            client_id: self.local_id.clone(),
            public_key: self.keypair.public_key(),
        }
    }

    pub fn peer_key_event(&self) -> WireEvent {
        WireEvent::PeerKey {
            from: self.local_id.clone(),
            to: self.peer_id.clone(),
            public_key: self.keypair.public_key(),
        }
    }

    pub fn is_ready(&self) -> bool {
        self.crypto_session.is_some()
    }

    pub fn handle_event(&mut self, event: WireEvent) -> Result<Option<String>, ClientSessionError> {
        match event {
            WireEvent::PeerKey {
                from,
                to,
                public_key,
            } => {
                if from != self.peer_id || to != self.local_id {
                    return Err(ClientSessionError::UnexpectedPeerKey);
                }
                if let Some(peer_public_key) = self.peer_public_key {
                    if peer_public_key == public_key {
                        return Ok(None);
                    }

                    return Err(ClientSessionError::UnexpectedPeerKey);
                }

                if let Some(expected) = &self.expected_peer_fingerprint
                    && fingerprint(&public_key) != *expected
                {
                    return Err(ClientSessionError::PeerKeyFingerprintMismatch);
                }
                self.peer_public_key = Some(public_key);
                self.crypto_session = Some(CryptoSession::new(
                    &self.keypair,
                    public_key,
                    self.local_id.clone(),
                    self.peer_id.clone(),
                ));
                Ok(None)
            }
            WireEvent::EncryptedMessage(envelope) => {
                let session = self
                    .crypto_session
                    .as_mut()
                    .ok_or(ClientSessionError::MissingPeerKey)?;
                let plaintext = session.decrypt(&envelope)?;
                let message =
                    String::from_utf8(plaintext).map_err(|_| ClientSessionError::InvalidUtf8)?;

                Ok(Some(message))
            }
            WireEvent::ClientHello { .. } | WireEvent::Ack { .. } | WireEvent::Error { .. } => {
                Ok(None)
            }
        }
    }

    pub fn encrypt_line(&mut self, line: &str) -> Result<WireEvent, ClientSessionError> {
        let session = self
            .crypto_session
            .as_mut()
            .ok_or(ClientSessionError::MissingPeerKey)?;
        let envelope = session.encrypt(MessageId::new(), line.as_bytes())?;

        Ok(WireEvent::EncryptedMessage(envelope))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientSessionError {
    MissingPeerKey,
    UnexpectedPeerKey,
    PeerKeyFingerprintMismatch,
    InvalidUtf8,
    Crypto(CryptoError),
}

impl From<CryptoError> for ClientSessionError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chat_core::event::WireEvent;
    use chat_core::types::ClientId;

    #[test]
    fn builds_hello_and_peer_key_without_plaintext() {
        let session = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );

        let hello = session.client_hello();
        let peer_key = session.peer_key_event();

        assert!(matches!(hello, WireEvent::ClientHello { .. }));
        assert!(matches!(peer_key, WireEvent::PeerKey { .. }));
    }

    #[test]
    fn encrypts_and_decrypts_line_after_peer_key_exchange() {
        let mut alice = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let mut bob = ClientSession::new(
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );

        bob.handle_event(alice.peer_key_event()).expect("alice key");
        alice.handle_event(bob.peer_key_event()).expect("bob key");

        let event = alice.encrypt_line("hello bob").expect("encrypt");
        let decrypted = bob.handle_event(event).expect("decrypt").expect("message");

        assert_eq!(decrypted, "hello bob");
    }

    #[test]
    fn reports_ready_after_peer_key_exchange() {
        let mut alice = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let bob = ClientSession::new(
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );

        assert!(!alice.is_ready());

        alice.handle_event(bob.peer_key_event()).expect("bob key");

        assert!(alice.is_ready());
    }

    #[test]
    fn accepts_peer_key_matching_expected_fingerprint() {
        let mut alice = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let bob = ClientSession::new(
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );
        let bob_peer_key = bob.peer_key_event();
        let pinned = fingerprint(&match bob_peer_key {
            WireEvent::PeerKey { public_key, .. } => public_key,
            other => panic!("expected peer key event, got {other:?}"),
        });
        alice.expect_peer_fingerprint(pinned);

        alice.handle_event(bob_peer_key).expect("matching peer key");

        assert!(alice.is_ready());
    }

    #[test]
    fn rejects_mismatched_fingerprint_and_stays_unready() {
        // MITM이 키를 바꿔치기해도 기대 지문과 다르면 세션이 열리지 않아야 한다.
        let mut alice = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let mallory = ClientSession::new(
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );
        alice.expect_peer_fingerprint(fingerprint(&PublicKeyBytes::from_array([9; 32])));

        let mallory_event = mallory.peer_key_event();
        assert_eq!(
            alice.handle_event(mallory_event),
            Err(ClientSessionError::PeerKeyFingerprintMismatch)
        );
        assert!(!alice.is_ready());
        assert!(alice.encrypt_line("hello").is_err());
    }

    #[test]
    fn reports_received_peer_fingerprint_for_display() {
        let mut alice = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let bob = ClientSession::new(
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );

        assert!(alice.peer_fingerprint().is_none());

        let bob_event = bob.peer_key_event();
        let expected = fingerprint(&match bob_event {
            WireEvent::PeerKey { public_key, .. } => public_key,
            other => panic!("expected peer key event, got {other:?}"),
        });
        alice.handle_event(bob_event).expect("peer key");

        assert_eq!(alice.peer_fingerprint(), Some(expected));
    }

    #[test]
    fn keeps_replay_protection_after_duplicate_peer_key() {
        let mut alice = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let mut bob = ClientSession::new(
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );
        let alice_key = alice.peer_key_event();

        bob.handle_event(alice_key.clone()).expect("alice key");
        alice.handle_event(bob.peer_key_event()).expect("bob key");
        let event = alice.encrypt_line("hello bob").expect("encrypt");
        bob.handle_event(event.clone()).expect("first decrypt");

        bob.handle_event(alice_key).expect("duplicate peer key");

        assert_eq!(
            bob.handle_event(event),
            Err(ClientSessionError::Crypto(CryptoError::DuplicateNonce))
        );
    }

    #[test]
    fn rejects_changed_peer_key_after_session_ready() {
        let alice = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let mallory_as_alice = ClientSession::new(
            ClientId::parse("alice").expect("alice"),
            ClientId::parse("bob").expect("bob"),
        );
        let mut bob = ClientSession::new(
            ClientId::parse("bob").expect("bob"),
            ClientId::parse("alice").expect("alice"),
        );

        bob.handle_event(alice.peer_key_event()).expect("alice key");

        assert_eq!(
            bob.handle_event(mallory_as_alice.peer_key_event()),
            Err(ClientSessionError::UnexpectedPeerKey)
        );
    }
}
