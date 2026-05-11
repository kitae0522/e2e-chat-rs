use serde::{Deserialize, Serialize};

use crate::types::{Ciphertext, ClientId, MessageId, NonceBytes, PublicKeyBytes};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub sender: ClientId,
    pub recipient: ClientId,
    pub message_id: MessageId,
    pub nonce: NonceBytes,
    pub ciphertext: Ciphertext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WireEvent {
    ClientHello {
        client_id: ClientId,
        public_key: PublicKeyBytes,
    },
    PeerKey {
        from: ClientId,
        to: ClientId,
        public_key: PublicKeyBytes,
    },
    EncryptedMessage(EncryptedEnvelope),
    Ack {
        message_id: MessageId,
    },
    Error {
        code: String,
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Ciphertext, ClientId, MessageId, NonceBytes, PublicKeyBytes, TypeError};

    #[test]
    fn serializes_encrypted_message_without_plaintext_field() {
        let event = WireEvent::EncryptedMessage(EncryptedEnvelope {
            sender: ClientId::parse("alice").expect("valid sender"),
            recipient: ClientId::parse("bob").expect("valid recipient"),
            message_id: MessageId::new(),
            nonce: NonceBytes::from_array([7; 24]),
            ciphertext: Ciphertext::from_bytes(vec![1, 2, 3, 4]),
        });

        let encoded = serde_json::to_string(&event).expect("serialize event");

        assert!(encoded.contains("\"type\":\"encrypted_message\""));
        assert!(!encoded.contains("plaintext"));
    }

    #[test]
    fn rejects_empty_client_id() {
        let err = ClientId::parse(" ").expect_err("empty id must fail");

        assert_eq!(err, TypeError::EmptyClientId);
    }

    #[test]
    fn peer_key_event_binds_sender_and_recipient() {
        let event = WireEvent::PeerKey {
            from: ClientId::parse("alice").expect("valid sender"),
            to: ClientId::parse("bob").expect("valid recipient"),
            public_key: PublicKeyBytes::from_array([9; 32]),
        };

        let encoded = serde_json::to_string(&event).expect("serialize event");

        assert!(encoded.contains("\"from\":\"alice\""));
        assert!(encoded.contains("\"to\":\"bob\""));
    }
}
