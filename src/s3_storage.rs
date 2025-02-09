use aws_sdk_s3::config::{timeout::TimeoutConfig, Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::{Client, Config};
use derive_new::new;
use eyre::{Context, Result};

use std::env;
use std::{sync::OnceLock, time::Duration};

const ENV_CRED_KEY_ID: &str = "AWS_ACCESS_KEY_ID";
const ENV_CRED_KEY_SECRET: &str = "AWS_SECRET_ACCESS_KEY";

#[derive(Clone, new)]
/// Type for reading/writing to S3
pub struct S3Storage {
    /// The name of the bucket.
    pub bucket: String,
    /// The region of the bucket.
    pub region: Region,
    /// A client with AWS credentials.
    #[new(default)]
    pub authenticated_client: OnceLock<Client>,
}

impl S3Storage {
    pub async fn write_to_bucket(&self, key: &str, body: &str) -> Result<()> {
        let client = self.get_authenticated_client().await?;

        let put_request = client
            .put_object()
            .bucket(self.bucket.clone())
            .key(key)
            .body(ByteStream::from(body.as_bytes().to_vec()))
            .content_type("application/json");

        match put_request.send().await {
            Ok(_) => Ok(()),
            Err(e) => {
                eprintln!("Failed to send put_object request: {:?}", e);
                Err(e).context("Failed to write to S3 bucket")
            }
        }
    }

    /// Retrieves the authenticated S3 client, initializing it if necessary.
    async fn get_authenticated_client(&self) -> Result<&Client> {
        let key_id = env::var(ENV_CRED_KEY_ID).context("Missing AWS_ACCESS_KEY_ID")?;
        let key_secret = env::var(ENV_CRED_KEY_SECRET).context("Missing AWS_SECRET_ACCESS_KEY")?;

        self.authenticated_client.get_or_init(|| {
            let credentials =
                Credentials::new(key_id, key_secret, None, None, "loaded-from-environment");

            let config = Config::builder()
                .region(self.region.clone())
                .credentials_provider(credentials)
                .timeout_config(
                    TimeoutConfig::builder()
                        .operation_timeout(Duration::from_secs(5))
                        .operation_attempt_timeout(Duration::from_millis(1500))
                        .build(),
                )
                .build();

            Client::from_conf(config)
        });

        Ok(self.authenticated_client.get().unwrap())
    }
}
