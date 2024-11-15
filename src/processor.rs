use async_trait::async_trait;
use crate::{checkpoint::SignedCheckpoint, signer::Signer};
use eyre::Error;
use crate::checkpoint::{CheckpointWithMessageId, Checkpoint};
use std::sync::Arc;
use crate::s3_storage::S3Storage;

#[async_trait]
pub trait Processor: Send + Sync {
    async fn submit_checkpoint(&self, checkpoint: CheckpointWithMessageId) -> Result<(), Error>;
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
    async fn submit_checkpoint(&self, checkpoint_with_id: CheckpointWithMessageId) -> Result<(), Error> {
        let signature = self.signer.sign(&checkpoint_with_id).await?;
        let serialized_signature: [u8; 65] = signature.into();

        let signed_checkpoint = SignedCheckpoint::new(checkpoint_with_id, signature, format!("0x{}", hex::encode(serialized_signature)));

        let serialized = serde_json::to_string_pretty(&signed_checkpoint)?;


        // save locally
        let file_path = format!("output/{}.json", checkpoint_with_id.message_id);
        std::fs::write(file_path, serialized)?;


        Ok(())
    }
}