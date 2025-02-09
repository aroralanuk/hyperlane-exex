use alloy_primitives::{keccak256, B256};
use eyre::{eyre, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct HyperlaneMessage {
    pub version: u8,
    pub nonce: u32,
    pub origin_domain: u32,
}

impl HyperlaneMessage {
    // Define offsets based on the Solidity library
    const VERSION_OFFSET: usize = 0;
    const NONCE_OFFSET: usize = 1;
    const ORIGIN_OFFSET: usize = 5;
    const SENDER_OFFSET: usize = 9;
    const BODY_OFFSET: usize = 77;

    /// Decodes a byte slice into a `HyperlaneMessage` struct.
    pub fn decode(message: &[u8]) -> Result<Self> {
        // Ensure the message is long enough to contain all fixed fields
        if message.len() < Self::BODY_OFFSET {
            return Err(eyre!(
                "Message too short: expected at least {} bytes, got {}",
                Self::BODY_OFFSET,
                message.len()
            ));
        }

        // Extract and parse each field using the defined offsets
        let version = message[Self::VERSION_OFFSET];

        let nonce = u32::from_be_bytes(
            message[Self::NONCE_OFFSET..Self::ORIGIN_OFFSET]
                .try_into()
                .unwrap(),
        );
        let origin_domain = u32::from_be_bytes(
            message[Self::ORIGIN_OFFSET..Self::SENDER_OFFSET]
                .try_into()
                .unwrap(),
        );
        Ok(HyperlaneMessage {
            version,
            nonce,
            origin_domain,
        })
    }

    pub fn id(message: &[u8]) -> B256 {
        keccak256(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;

    #[test]
    fn test_decode_message() {
        let encoded_message =
            &hex!(
                "03000d9030000021050000000000000000000000009f1f6357284526489e8e6ce4b2cb2612aa1d47120000a4b10000000000000000000000009f1f6357284526489e8e6ce4b2cb2612aa1d471200000000000000000000000000000000000000000000000000000000000000200000000000002105789ce9072157131c9e76d34d7468e57c354015d7010001000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000002017d7cef0099e01e45db1ab778fadd8943bfeab45e0000270b60a831d71e27922"
            );
        let message = HyperlaneMessage::decode(encoded_message).unwrap();
        assert_eq!(message.version, 3);
        assert_eq!(message.nonce, 888880);
        assert_eq!(message.origin_domain, 8453);
    }
}
