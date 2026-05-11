use chat_core::crypto::{CryptoError, CryptoSession, KeyPair};
use chat_core::event::WireEvent;
use chat_core::nonce::{NonceError, NonceTracker};
use chat_core::types::{ClientId, MessageId, NonceBytes};

pub struct ClientSession {
    local_id: ClientId,
    peer_id: ClientId,
    keypair: KeyPair,
    crypto_session: Option<CryptoSession>,
    inbound_nonces: NonceTracker,
    next_outbound_nonce: u64,
}

impl ClientSession {
    pub fn new(local_id: ClientId, peer_id: ClientId) -> Self {
        Self {
            local_id,
            peer_id,
            keypair: KeyPair::generate(),
            crypto_session: None,
            inbound_nonces: NonceTracker::default(),
            next_outbound_nonce: 0,
        }
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
                    .as_ref()
                    .ok_or(ClientSessionError::MissingPeerKey)?;
                let plaintext = session.decrypt(&envelope)?;
                self.inbound_nonces.mark_seen(envelope.nonce)?;
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
        if self.crypto_session.is_none() {
            return Err(ClientSessionError::MissingPeerKey);
        }

        let nonce = self.next_nonce()?;
        let Some(session) = self.crypto_session.as_ref() else {
            return Err(ClientSessionError::MissingPeerKey);
        };
        let envelope = session.encrypt(MessageId::new(), nonce, line.as_bytes())?;

        Ok(WireEvent::EncryptedMessage(envelope))
    }

    fn next_nonce(&mut self) -> Result<NonceBytes, ClientSessionError> {
        self.next_outbound_nonce = self
            .next_outbound_nonce
            .checked_add(1)
            .ok_or(ClientSessionError::NonceExhausted)?;

        let mut nonce = [0u8; 24];
        nonce[16..].copy_from_slice(&self.next_outbound_nonce.to_be_bytes());
        Ok(NonceBytes::from_array(nonce))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientSessionError {
    MissingPeerKey,
    UnexpectedPeerKey,
    NonceExhausted,
    InvalidUtf8,
    Crypto(CryptoError),
    Nonce(NonceError),
}

impl From<CryptoError> for ClientSessionError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<NonceError> for ClientSessionError {
    fn from(error: NonceError) -> Self {
        Self::Nonce(error)
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
}
