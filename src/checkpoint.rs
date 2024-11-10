use serde::{Serialize, Deserialize};
use alloy_primitives::{keccak256, B256};

pub trait Signable: Send + Sync {
    /// Computes and returns the signing hash of the object.
    fn signing_hash(&self) -> B256;
}

/// A checkpoint for a message ID.
#[derive(Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct Checkpoint {
    /// The merkle tree hook address
    pub merkle_tree_hook_address: B256,
    /// The mailbox / merkle tree hook domain
    pub mailbox_domain: u32,
    /// The checkpointed root
    pub root: B256,
    /// The index of the checkpoint
    pub index: u32,
}

#[derive(Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct CheckpointWithMessageId {
    /// existing Hyperlane checkpoint struct
    pub checkpoint: Checkpoint,
    /// hash of message emitted from mailbox checkpoint.index
    pub message_id: B256,
}



impl Signable for CheckpointWithMessageId {
    /// Computes the EIP-191 compliant signing hash for the checkpoint.
    fn signing_hash(&self) -> B256 {
        // Compute the signing hash:
        // domain_hash(mailbox_address, mailbox_domain) || root || index (as u32) || message_id
        let domain = domain_hash(
            self.checkpoint.merkle_tree_hook_address.into(),
            self.checkpoint.mailbox_domain,
        );
        
        let mut bytes = Vec::new();
        bytes.extend_from_slice(domain.as_ref());
        bytes.extend_from_slice(self.checkpoint.root.as_ref());
        bytes.extend_from_slice(&self.checkpoint.index.to_be_bytes());
        bytes.extend_from_slice(self.message_id.as_ref());
        keccak256(bytes)
    }
}

pub fn domain_hash(address: B256, domain: impl Into<u32>) -> B256 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&domain.into().to_be_bytes());
    bytes.extend_from_slice(address.as_ref());  // Using as_ref() to get &[u8]
    bytes.extend_from_slice(b"HYPERLANE");
    keccak256(bytes)
}