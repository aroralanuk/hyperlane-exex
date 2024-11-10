use async_trait::async_trait;
use crate::signer::Signer;
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
    async fn submit_checkpoint(&self, checkpoint: CheckpointWithMessageId) -> Result<(), Error> {
        Ok(())
    }
}