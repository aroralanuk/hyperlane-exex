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
        self.signer.sign_hash(&hash).await.map_err(|e| eyre!("{}", e))
    }
}