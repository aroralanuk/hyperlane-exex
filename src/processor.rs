use async_trait::async_trait;
use crate::{checkpoint::{CheckpointWithMessageIdAndNonce, SignedCheckpoint}, signer::Signer};
use eyre::Error;
use crate::checkpoint::CheckpointWithMessageId;
use std::sync::Arc;
use crate::s3_storage::S3Storage;

#[async_trait]
pub trait Processor: Send + Sync {
    async fn submit_checkpoint(&self, checkpoint: CheckpointWithMessageIdAndNonce) -> Result<(), Error>;
}

pub struct S3Processor<S: Signer + Send + Sync + 'static> {
    signer: Arc<S>,
    s3_storage: Arc<S3Storage>,
}

impl<S: Signer + Send + Sync + 'static> S3Processor<S> {
    /// Creates a new CheckpointProcessor with the given signer and S3 storage.
    pub fn new(signer: Arc<S>, s3_storage: Arc<S3Storage>) -> Self {
        Self { signer, s3_storage }
    }
}

#[async_trait]
impl<S: Signer + Send + Sync + 'static> Processor for S3Processor<S> {
    async fn submit_checkpoint(&self, checkpoint_nonce: CheckpointWithMessageIdAndNonce) -> Result<(), Error> {
        let checkpoint_with_id = CheckpointWithMessageId {
            checkpoint: checkpoint_nonce.checkpoint,
            message_id: checkpoint_nonce.message_id,
        };
        let signature = self.signer.sign(&checkpoint_with_id).await?;
        let serialized_signature: [u8; 65] = signature.into();

        let signed_checkpoint = SignedCheckpoint::new(checkpoint_with_id, signature, format!("0x{}", hex::encode(serialized_signature)));

        let serialized = serde_json::to_string_pretty(&signed_checkpoint)?;

        // save to s3
        let nonce_key = format!("checkpoint_nonce_{}", checkpoint_nonce.nonce.to_string());
        self.s3_storage.write_to_bucket(&nonce_key, &serialized).await?;

        println!("submitted checkpoint to s3");

        Ok(())
    }
}