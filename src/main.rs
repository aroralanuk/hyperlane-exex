use alloy_primitives::{address, b256, Address};
use alloy_sol_types::{sol, SolEventInterface};
use aws_sdk_s3::config::Region;
use clap::Parser;
use futures_util::{FutureExt, TryStreamExt};
use k256::ecdsa::SigningKey;
use message::HyperlaneMessage;
use processor::{Processor, S3Processor};
use reth_exex::{ExExContext, ExExEvent, ExExNotification};
use reth_node_api::FullNodeComponents;
use reth_optimism_cli::{chainspec::OpChainSpecParser, Cli};
use reth_optimism_node::{args::RollupArgs, OpNode};
use reth_primitives::{Log, SealedBlockWithSenders, TransactionSigned};
use reth_provider::Chain;
use reth_tracing::tracing::info;
use s3_storage::S3Storage;
use signer::PrivateKeySigner;
use std::{env, sync::Arc};
use std::{
    future::Future,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::task::JoinHandle;

use Mailbox::MailboxEvents;

use crate::Mailbox::Dispatch;
sol!(Mailbox, "mailbox_abi.json");

mod checkpoint;
mod message;
mod processor;
mod s3_storage;
mod signer;

use checkpoint::{Checkpoint, CheckpointWithMessageIdAndNonce};

struct HyperlaneExEx<Node: FullNodeComponents> {
    /// The context of the ExEx
    ctx: ExExContext<Node>,
    /// processor for handling checkpoints
    processor: Arc<dyn Processor>,
}

impl<Node: FullNodeComponents> HyperlaneExEx<Node> {
    /// Create a new instance of the ExEx
    fn new(ctx: ExExContext<Node>, processor: Arc<dyn Processor>) -> Self {
        Self { ctx, processor }
    }
}

const MAILBOX_ADDRESS: Address = address!("eA87ae93Fa0019a82A727bfd3eBd1cFCa8f64f1D");

/// The initialization logic of the ExEx is just an async function.
///
/// During initialization you can wait for resources you need to be up for the ExEx to function,
/// like a database connection.
// async fn exex_init<Node: FullNodeComponents>(
//     ctx: ExExContext<Node>,
// ) -> eyre::Result<impl Future<Output = eyre::Result<()>>> {
//     Ok(exex(ctx))
// }

/// An ExEx is just a future, which means you can implement all of it in an async function!
///
/// This ExEx just prints out whenever either a new chain of blocks being added, or a chain of
/// blocks being re-orged. After processing the chain, emits an [ExExEvent::FinishedHeight] event.
///
/// In the case of hyperlane-exex, the ExEx filters out the [MailboxEvents::DispatchId] events from
/// the chain, signs them with a private key, and writes them to an S3 bucket. In the case of reorgs or reverts, we
/// delete the checkpoints from the S3 bucket in the [delete_checkpoints_from_s3] function.
impl<Node: FullNodeComponents + Unpin> Future for HyperlaneExEx<Node> {
    type Output = eyre::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        info!("Starting exex");

        let mut handles: Vec<JoinHandle<()>> = Vec::new();

        while let Some(notification) = ready!(this.ctx.notifications.try_next().poll_unpin(cx))? {
            match &notification {
                ExExNotification::ChainCommitted { new } => {
                    let committed_chain = notification.committed_chain().unwrap();
                    info!(committed_chain = ?new.range(), "Received commit");

                    let events = decode_chain_into_events(&committed_chain);

                    for (_, _, _, event) in events {
                        match event {
                            MailboxEvents::Dispatch(Dispatch {
                                sender,
                                destination,
                                recipient,
                                message,
                            }) => {
                                info!(
                                    "Dispatch: sender: {}, destination: {}, recipient: {}",
                                    sender, destination, recipient
                                );

                                let decoded_message = match HyperlaneMessage::decode(&message) {
                                    Ok(msg) => msg,
                                    Err(e) => {
                                        eprintln!("Failed to decode HyperlaneMessage: {:?}", e);
                                        continue;
                                    }
                                };

                                let checkpoint_with_id = CheckpointWithMessageIdAndNonce {
                                    message_id: HyperlaneMessage::id(&message),
                                    checkpoint: Checkpoint {
                                        merkle_tree_hook_address: b256!("0000000000000000000000000000000000000000000000000000000000000000"),
                                        mailbox_domain: decoded_message.origin_domain,
                                        root: b256!("0000000000000000000000000000000000000000000000000000000000000000"),
                                        // index: decoded_message.nonce,
                                        index: 0,
                                    },
                                    nonce: decoded_message.nonce,
                                };

                                let processor = Arc::clone(&this.processor);
                                info!("Checking to submit checkpoint...");
                                let handle = tokio::spawn(async move {
                                    if let Err(e) =
                                        processor.submit_checkpoint(checkpoint_with_id).await
                                    {
                                        eprintln!("Failed to submit checkpoint: {:?}", e);
                                    }
                                });
                                handles.push(handle);
                            }
                            _ => {}
                        }
                    }
                }
                ExExNotification::ChainReorged { old, new } => {
                    let _reverted_chain = notification.reverted_chain().unwrap();
                    info!(reverted_chain = ?old.range(), to_chain = ?new.range(), "Received reorg");
                }
                ExExNotification::ChainReverted { old } => {
                    info!(reverted_chain = ?old.range(), "Received revert");

                    // delete_checkpoints_from_s3(&s3_instance, &reverted_chain).await?;
                }
            };

            // Send a finished height event, signaling the node that we don't need any blocks below
            // this height anymore
            if let Some(committed_chain) = notification.committed_chain() {
                this.ctx
                    .events
                    .send(ExExEvent::FinishedHeight(committed_chain.tip().num_hash()))?;
            }
        }

        for handle in handles {
            tokio::pin!(handle);
            match handle.poll_unpin(cx) {
                Poll::Ready(result) => {
                    if let Err(e) = result {
                        eprintln!("Task failed: {:?}", e);
                    }
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }
}

/// Decode chain of blocks into a flattened list of receipt logs, and filter only
/// [MailboxEvents].
fn decode_chain_into_events(
    chain: &Chain,
) -> impl Iterator<
    Item = (
        &SealedBlockWithSenders,
        &TransactionSigned,
        &Log,
        MailboxEvents,
    ),
> {
    chain
        // Get all blocks and receipts
        .blocks_and_receipts()
        // Get all receipts
        .flat_map(|(block, receipts)| {
            block
                .body
                .transactions()
                .zip(receipts.iter().flatten())
                .map(move |(tx, receipt)| (block, tx, receipt))
        })
        // Get all logs from the mailbox contract
        .flat_map(|(block, tx, receipt)| {
            receipt
                .logs
                .iter()
                .filter(|log| log.address == MAILBOX_ADDRESS)
                .map(move |log| (block, tx, log))
        })
        // Decode and filter bridge events
        .filter_map(|(block, tx, log)| {
            info!(
                "Decoding log: {:?}, block number: {}, tx to: {}",
                log,
                block.number,
                tx.transaction.to().unwrap()
            );
            MailboxEvents::decode_raw_log(log.topics(), &log.data.data, true)
                .ok()
                .map(|event| (block, tx, log, event))
        })
}

fn main() -> eyre::Result<()> {
    Cli::<OpChainSpecParser, RollupArgs>::parse().run(|builder, _| async move {
        // Initialize the signer
        let private_key_str =
            env::var("PRIVATE_KEY").expect("PRIVATE_KEY environment variable not set");
        let private_key_bytes = hex::decode(private_key_str.trim_start_matches("0x"))?;
        let signing_key = SigningKey::from_slice(&private_key_bytes)
            .map_err(|_| eyre::eyre!("Invalid private key format"))?;
        let signer = Arc::new(PrivateKeySigner::new(signing_key));

        let s3_instance = Arc::new(S3Storage::new(
            "hyperlane-validator-signatures-ethereum".to_string(),
            Region::new("us-east-2"),
        ));

        let processor = Arc::new(S3Processor::new(signer, s3_instance));

        let handle = builder
            .node(OpNode::default())
            .install_exex("hyperlane-exex", |ctx| async move {
                Ok(HyperlaneExEx::new(ctx, processor))
            })
            .launch()
            .await?;

        handle.wait_for_node_exit().await
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Header, TxEip1559};
    use alloy_primitives::{address, Address, TxKind};

    use alloy_primitives::hex;
    use alloy_sol_types::SolEvent;
    use reth::revm::db::BundleState;
    use reth_execution_types::{Chain, ExecutionOutcome};
    use reth_exex_test_utils::{test_exex_context, PollOnce};
    use reth_primitives::{Block, BlockBody, Log, Receipt, Transaction, TransactionSigned, TxType};
    use reth_testing_utils::generators::sign_tx_with_random_key_pair;
    use std::{pin::pin, time::Duration};

    use crate::Mailbox::Dispatch;

    fn construct_tx_and_receipt(
        to: Address,
        events: Vec<Log>,
    ) -> eyre::Result<(TransactionSigned, Receipt)> {
        let tx = Transaction::Eip1559(TxEip1559 {
            to: TxKind::Call(to),
            ..Default::default()
        });

        let receipt = Receipt {
            tx_type: TxType::Eip1559,
            success: true,
            cumulative_gas_used: 0,
            logs: events,
            ..Default::default()
        };
        Ok((
            sign_tx_with_random_key_pair(&mut rand::thread_rng(), tx),
            receipt,
        ))
    }

    #[tokio::test]
    async fn test_exex() -> eyre::Result<()> {
        // Instantiate a deterministic signing key for testing
        let private_key_str =
            env::var("PRIVATE_KEY").expect("PRIVATE_KEY environment variable not set");
        let signing_key =
            SigningKey::from_slice(&hex::decode(private_key_str.trim_start_matches("0x")).unwrap())
                .unwrap();
        let signer = Arc::new(PrivateKeySigner::new(signing_key));

        // Instantiate a mock or in-memory S3Storage for testing
        let s3_instance = Arc::new(S3Storage::new(
            "test-bucket".to_string(),
            Region::new("us-east-2"),
        ));
        let processor = Arc::new(S3Processor::new(signer, s3_instance));

        let (ctx, handle) = test_exex_context().await?;
        let mut exex = pin!(HyperlaneExEx::new(ctx, processor));

        // Generate random "from" and "to" addresses for deposit and withdrawal events
        let from_address = Address::random();
        let dest_mailbox = address!("d4C1905BB1D26BC93DAC913e13CaCC278CdCC80D");
        let to_address = b256!("000000000000000000000000acEB607CdF59EB8022Cc0699eEF3eCF246d149e2");
        let dispatch_event = Dispatch {
            sender: from_address,
            destination: 42161,
            recipient: to_address, message: (&hex!(
                "03000da599000021050000000000000000000000005ed594a8f805bdd36fb1c9f1fc9a9cb94ac954c60000a4b1000000000000000000000000bdea34e4bc7316c6c397f17e6a95966579ba9e1600000000000000000000000096fbe82dc7f08641b7f5524b9874638adfd2796000000000000000000000000000000000000000000000000001301cbf18c600000000000000000000000000000000000000000000"
            )).into()
        };

        let dispatch_log = Log::new(
            dest_mailbox,
            dispatch_event
                .encode_topics()
                .into_iter()
                .map(|topic| topic.0)
                .collect(),
            dispatch_event.encode_data().into(),
        )
        .ok_or_else(|| eyre::eyre!("failed to encode dispatch event"))?;

        let (dispatch_tx, dispatch_tx_receipt) =
            construct_tx_and_receipt(dest_mailbox, vec![dispatch_log])?;

        let block = Block {
            header: Header::default(),
            body: BlockBody {
                transactions: vec![dispatch_tx],
                ..Default::default()
            },
        }
        .seal_slow()
        .seal_with_senders()
        .ok_or_else(|| eyre::eyre!("failed to seal block"))?;

        // Construct a chain
        let chain = Chain::new(
            vec![block.clone()],
            ExecutionOutcome::new(
                BundleState::default(),
                vec![dispatch_tx_receipt].into(),
                block.number,
                vec![],
            ),
            None,
        );

        // Send a notification that the chain has been committed
        handle
            .send_notification_chain_committed(chain.clone())
            .await?;
        // Poll the ExEx once, it will process the notification that we just sent
        exex.poll_once().await?;

        // Await all pending tasks in the runtime
        tokio::task::yield_now().await;

        Ok(())
    }

    #[tokio::test]
    // #[traced_test]
    async fn test_exex_new() -> eyre::Result<()> {
        // Instantiate a deterministic signing key for testing
        let private_key_str =
            env::var("PRIVATE_KEY").expect("PRIVATE_KEY environment variable not set");
        let signing_key =
            SigningKey::from_slice(&hex::decode(private_key_str.trim_start_matches("0x")).unwrap())
                .unwrap();
        let signer = Arc::new(PrivateKeySigner::new(signing_key));

        // Instantiate a mock or in-memory S3Storage for testing
        let s3_instance = Arc::new(S3Storage::new(
            "hyperlane-validator-signatures-exex-base".to_string(),
            Region::new("us-east-2"),
        ));
        let processor = Arc::new(S3Processor::new(signer, s3_instance));

        let (ctx, handle) = test_exex_context().await?;
        let mut exex = pin!(HyperlaneExEx::new(ctx, processor));

        // Generate random "from" and "to" addresses for deposit and withdrawal events
        let from_address = Address::random();
        let dest_mailbox = address!("d4C1905BB1D26BC93DAC913e13CaCC278CdCC80D");
        let to_address = b256!("000000000000000000000000acEB607CdF59EB8022Cc0699eEF3eCF246d149e2");

        let dispatch_event = Dispatch {
            sender: from_address,
            destination: 42161,
            recipient: to_address, message: (&hex!(
                "03000daf1f00002105000000000000000000000000b1b4e269dd0d19d9d49f3a95bf6c2c15f13e79430000a4b10000000000000000000000008a646a71c6717bb99fc45a3e1faf094938eb82fd68656c6c6f20776f726c64"
            )).into()
        };

        let dispatch_log = Log::new(
            dest_mailbox,
            dispatch_event
                .encode_topics()
                .into_iter()
                .map(|topic| topic.0)
                .collect(),
            dispatch_event.encode_data().into(),
        )
        .ok_or_else(|| eyre::eyre!("failed to encode dispatch event"))?;

        let (dispatch_tx, dispatch_tx_receipt) =
            construct_tx_and_receipt(dest_mailbox, vec![dispatch_log])?;

        let block = Block {
            header: Header::default(),
            body: BlockBody {
                transactions: vec![dispatch_tx],
                ..Default::default()
            },
        }
        .seal_slow()
        .seal_with_senders()
        .ok_or_else(|| eyre::eyre!("failed to seal block"))?;

        // Construct a chain
        let chain = Chain::new(
            vec![block.clone()],
            ExecutionOutcome::new(
                BundleState::default(),
                vec![dispatch_tx_receipt].into(),
                block.number,
                vec![],
            ),
            None,
        );

        // Send a notification that the chain has been committed
        handle
            .send_notification_chain_committed(chain.clone())
            .await?;
        // Poll the ExEx once, it will process the notification that we just sent
        exex.poll_once().await?;

        // Await all pending tasks in the runtime
        tokio::task::yield_now().await;

        tokio::time::sleep(Duration::from_secs(3)).await;

        Ok(())
    }
}
