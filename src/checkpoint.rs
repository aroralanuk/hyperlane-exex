use alloy_primitives::{keccak256, Signature, B256};
use derive_new::new;
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};

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

#[derive(Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct CheckpointWithMessageIdAndNonce {
    /// existing Hyperlane checkpoint struct
    pub checkpoint: Checkpoint,
    /// hash of message emitted from mailbox checkpoint.index
    pub message_id: B256,
    /// nonce of the message
    pub nonce: u32,
}

#[derive(Debug, Serialize, Deserialize, new)]
pub struct SignedCheckpoint {
    /// The checkpoint value
    pub value: CheckpointWithMessageId,
    /// The signature components
    #[serde(serialize_with = "serialize_signature")]
    pub signature: Signature,
    /// The serialized signature string
    #[serde(rename = "serialized_signature")]
    pub serialized_signature: String,
}

fn serialize_signature<S: Serializer>(
    signature: &Signature,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut state = serializer.serialize_struct("Signature", 3)?;
    state.serialize_field("r", &signature.r())?;
    state.serialize_field("s", &signature.s())?;
    state.serialize_field("v", &signature.v().y_parity_byte_non_eip155())?;
    state.end()
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
        let hash = keccak256(bytes);
        hash
    }
}

pub fn domain_hash(address: B256, domain: impl Into<u32>) -> B256 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&domain.into().to_be_bytes());
    bytes.extend_from_slice(address.as_ref());
    bytes.extend_from_slice(b"HYPERLANE");
    keccak256(bytes)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::b256;

    use super::*;

    #[test]
    fn test_checkpoint_signing_hash() {
        // from https://explorer.hyperlane.xyz/message/0x0f3c2a91d6aa7c2c35077588db4882ad65e3e315520a295d6750cf0e3e9b8764
        let checkpoint = Checkpoint {
            merkle_tree_hook_address: b256!(
                "00000000000000000000000019dc38aeae620380430c200a6e990d5af5480117"
            ),
            mailbox_domain: 8453,
            root: b256!("f4c3496c966c086cf403aa90d7a76cd2b9a6e4a231a995a46f52602132363367"),
            index: 891473,
        };

        let checkpoint_with_message = CheckpointWithMessageId {
            checkpoint,
            message_id: b256!("0f3c2a91d6aa7c2c35077588db4882ad65e3e315520a295d6750cf0e3e9b8764"),
        };

        let hash = checkpoint_with_message.signing_hash();
        assert_eq!(
            hash,
            b256!("a846779094ecec23118e978c7ef817eafb8df8b305b4fe4adbe07e22fd5f97ea")
        );
    }
}
