use alloy_sol_types::{sol, SolCall};
use alloy_primitives::hex;
use eyre::{eyre, Result};

// sol!(
//     #[derive(Debug, PartialEq, Eq)]
//     function decodeMessage(bytes memory encodedMessage) external view returns (uint8 version, uint32 nonce, uint32 originDomain, bytes32 sender, uint32 destinationDomain, bytes32 recipient);
// );

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct HyperlaneMessage {
    pub version: u8,
    pub nonce: u32,
}

impl HyperlaneMessage {
    // Define offsets based on the Solidity library
    const VERSION_OFFSET: usize = 0;
    const NONCE_OFFSET: usize = 1;
    const ORIGIN_OFFSET: usize = 5;
    const BODY_OFFSET: usize = 77;

    /// Decodes a byte slice into a `HyperlaneMessage` struct.
    pub fn decode(message: &[u8]) -> Result<Self> {
        // Ensure the message is long enough to contain all fixed fields
        if message.len() < Self::BODY_OFFSET {
            return Err(eyre!("Message too short: expected at least {} bytes, got {}", Self::BODY_OFFSET, message.len()));
        }

        // Extract and parse each field using the defined offsets
        let version = message[Self::VERSION_OFFSET];

        let nonce = u32::from_be_bytes(
            message[Self::NONCE_OFFSET..Self::ORIGIN_OFFSET]
                .try_into()
                .unwrap(),
        );
        Ok(HyperlaneMessage {
            version,
            nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_message() {
        let encoded_message =
            &hex!(
                "03000d9030000021050000000000000000000000009f1f6357284526489e8e6ce4b2cb2612aa1d47120000a4b10000000000000000000000009f1f6357284526489e8e6ce4b2cb2612aa1d471200000000000000000000000000000000000000000000000000000000000000200000000000002105789ce9072157131c9e76d34d7468e57c354015d7010001000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000002017d7cef0099e01e45db1ab778fadd8943bfeab45e0000270b60a831d71e27922"
            );
        let message = HyperlaneMessage::decode(encoded_message).unwrap();
        println!("{:?}", message);
    }
}
