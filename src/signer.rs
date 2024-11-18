use async_trait::async_trait;
use alloy_signer::{Signer as AlloySigner, Signature};
use k256::ecdsa::SigningKey;
use alloy_signer_local::LocalSigner;
use eyre::{Result, eyre};
use crate::checkpoint::Signable;
use std::sync::Arc;

#[async_trait]
pub trait Signer: Send + Sync {
    /// Signs the given data and returns a signature.
    async fn sign(&self, signable: &dyn Signable) -> Result<Signature>;
}

/// Implementation of Signer using a private key.
pub struct PrivateKeySigner {
    signer: Arc<dyn AlloySigner + Send + Sync>,
}

impl PrivateKeySigner {
    /// Creates a new PrivateKeySigner with the given private key.
    pub fn new(private_key: SigningKey) -> Self {
        Self {
            signer: Arc::new(LocalSigner::from_signing_key(private_key)),
        }
    }
}

#[async_trait]
impl Signer for PrivateKeySigner {
    async fn sign(&self, signable: &dyn Signable) -> Result<Signature> {
        let hash = signable.signing_hash();
        let primitive_signature = self.signer.sign_message(&hash.as_ref()).await.map_err(|e| eyre!("{}", e))?;
        Signature::from_signature_and_parity(primitive_signature.to_k256().unwrap(), primitive_signature.v())
            .map_err(|e| eyre!("{}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use alloy_primitives::b256;
    use crate::checkpoint::{Checkpoint, CheckpointWithMessageId};

    #[tokio::test]
    async fn test_signer() {
        let private_key_str = env::var("PRIVATE_KEY").expect("PRIVATE_KEY environment variable not set");
        let signing_key = SigningKey::from_slice(&hex::decode(private_key_str.trim_start_matches("0x")).unwrap()).unwrap();
        let signer = Arc::new(PrivateKeySigner::new(signing_key));

        let checkpoint = CheckpointWithMessageId {
            checkpoint: Checkpoint {
                merkle_tree_hook_address: b256!("00000000000000000000000019dc38aeae620380430c200a6e990d5af5480117"),
                mailbox_domain: 8453,
                root: b256!("0a6765ba86e0fe13c871ab982d54fb637812573c9792c4744b35a34005c70c92"),
                index: 894361,
            },
            message_id: b256!("a8cffe04926e2dba26c4770dc627dd8f0a86fc3898b2396bb7a54a08497791d0"),
        };

        let signature = signer.sign(&checkpoint).await.unwrap();

        let serialized_signature: [u8; 65] = signature.into();

        assert_eq!("0x".to_string() + &hex::encode(serialized_signature), "0x3fff5e542a759fea182a555cfd7a01a710f9ffad9b5106caf9407554d410b5926c96df2855a6158cfe9911e3ee8e966062586c76b19b206fde6db98b142912bd1b");
    }
}