use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TypeError {
    #[error("client id cannot be empty")]
    EmptyClientId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ClientId(String);

impl ClientId {
    pub fn parse(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(TypeError::EmptyClientId);
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ClientId {
    type Error = TypeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<ClientId> for String {
    fn from(value: ClientId) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(Uuid);

impl MessageId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyBytes([u8; 32]);

impl PublicKeyBytes {
    pub fn from_array(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NonceBytes([u8; 24]);

impl NonceBytes {
    pub fn from_array(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    pub fn as_array(&self) -> &[u8; 24] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext(Vec<u8>);

impl Ciphertext {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
