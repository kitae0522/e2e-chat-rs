use std::collections::HashSet;

use thiserror::Error;

use crate::types::NonceBytes;

#[derive(Debug, Default, Clone)]
pub struct NonceTracker {
    seen: HashSet<NonceBytes>,
}

impl NonceTracker {
    pub fn mark_seen(&mut self, nonce: NonceBytes) -> Result<(), NonceError> {
        if self.seen.insert(nonce) {
            Ok(())
        } else {
            Err(NonceError::DuplicateNonce)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NonceError {
    #[error("nonce was already used in this session")]
    DuplicateNonce,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NonceBytes;

    #[test]
    fn rejects_duplicate_nonce() {
        let mut tracker = NonceTracker::default();
        let nonce = NonceBytes::from_array([6; 24]);

        tracker.mark_seen(nonce).expect("first nonce");

        assert_eq!(tracker.mark_seen(nonce), Err(NonceError::DuplicateNonce));
    }
}
