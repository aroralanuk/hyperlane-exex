use async_trait::async_trait;
use derive_new::new;
use eyre::Result;
use rusoto_core::{
    credential::{
        AutoRefreshingProvider, AwsCredentials, CredentialsError, EnvironmentProvider,
        ProvideAwsCredentials,
    },
    HttpClient, HttpConfig, Region,
};
use rusoto_s3::{PutObjectRequest, S3Client, S3};
use rusoto_sts::WebIdentityProvider;
use std::{sync::OnceLock, time::Duration};
use tokio::time::timeout;

/// from hyperlane-base
/// The timeout for S3 requests. Rusoto doesn't offer timeout configuration
/// out of the box, so S3 requests must be wrapped with a timeout.
/// See https://github.com/rusoto/rusoto/issues/1795.
const S3_REQUEST_TIMEOUT_SECONDS: u64 = 30;
/// See https://github.com/hyperium/hyper/issues/2136#issuecomment-589488526
pub const HYPER_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// Provides AWS credentials from multiple possible sources using a priority order.
/// The following sources are checked in order for credentials when calling credentials. More sources may be supported in future if a need be.
/// 1) Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.
/// 2) `WebIdentityProvider`: by default, configured from environment variables `AWS_WEB_IDENTITY_TOKEN_FILE`,
pub(crate) struct AwsChainCredentialsProvider {
    environment_provider: EnvironmentProvider,
    web_identity_provider: AutoRefreshingProvider<WebIdentityProvider>,
}

impl AwsChainCredentialsProvider {
    pub fn new() -> Self {
        // Wrap the `WebIdentityProvider` to a caching `AutoRefreshingProvider`.
        // By default, the `WebIdentityProvider` requests AWS Credentials on each call to `credentials()`
        // To save the CPU/network and AWS bills, the `AutoRefreshingProvider` allows to cache the credentials until the expire.
        let auto_refreshing_provider =
            AutoRefreshingProvider::new(WebIdentityProvider::from_k8s_env())
                .expect("Always returns Ok(...)");
        AwsChainCredentialsProvider {
            environment_provider: EnvironmentProvider::default(),
            web_identity_provider: auto_refreshing_provider,
        }
    }
}

#[async_trait]
impl ProvideAwsCredentials for AwsChainCredentialsProvider {
    async fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
        if let Ok(creds) = self.environment_provider.credentials().await {
            Ok(creds)
        } else {
            // Propagate errors from the 'WebIdentityProvider'.
            self.web_identity_provider.credentials().await
        }
    }
}

#[derive(Clone, new)]
/// Type for reading/writing to S3
pub struct S3Storage {
    /// The name of the bucket.
    pub bucket: String,
    /// The region of the bucket.
    pub region: Region,
    /// A client with AWS credentials.
    #[new(default)]
    pub authenticated_client: OnceLock<S3Client>,
}

impl S3Storage {
    pub async fn write_to_bucket(&self, key: String, body: &str) -> Result<(), std::io::Error> {
        let req = PutObjectRequest {
            key: key,
            bucket: self.bucket.clone(),
            body: Some(Vec::from(body).into()),
            content_type: Some("application/json".to_owned()),
            ..Default::default()
        };
        let _ = timeout(
            Duration::from_secs(S3_REQUEST_TIMEOUT_SECONDS),
            self.authenticated_client().put_object(req),
        )
        .await?;
        Ok(())
    }

    pub async fn delete_from_bucket(&self, key: String) -> Result<(), std::io::Error> {
        let req = rusoto_s3::DeleteObjectRequest {
            key: key,
            bucket: self.bucket.clone(),
            ..Default::default()
        };
        let _ = timeout(
            Duration::from_secs(S3_REQUEST_TIMEOUT_SECONDS),
            self.authenticated_client().delete_object(req),
        )
        .await?;
        Ok(())
    }

    /// note that the authenticated client is a OnceLock, so it will only be created once
    fn authenticated_client(&self) -> &S3Client {
        self.authenticated_client.get_or_init(|| {
            S3Client::new_with(
                <S3Storage as Clone>::clone(&self)
                    .http_client_with_timeout()
                    .unwrap(),
                AwsChainCredentialsProvider::new(),
                self.region.clone(),
            )
        })
    }

    pub fn http_client_with_timeout(self) -> Result<HttpClient> {
        let mut config = HttpConfig::new();
        config.pool_idle_timeout(HYPER_POOL_IDLE_TIMEOUT);
        Ok(HttpClient::new_with_config(config)?)
    }
}
