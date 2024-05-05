
use hyperlane_core::{Signable, H256};
use serde::Serialize;

/// A checkpoint for a message ID.
#[derive(Copy, Clone, Serialize, Debug)]
pub struct MessageIdCheckpoint {
    pub message_id: [u8; 32],
}

// pub type SignedMessageIdCheckpoint = SignedType<MessageIdCheckpoint>;

impl Signable for MessageIdCheckpoint {
    fn signing_hash(&self) -> H256 {
        self.message_id.into()
    }
}

pub fn checkpoint_key(message_id: [u8; 32]) -> String {
    format!("checkpoint_with_messageId_{}.json", hex::encode(message_id))
}