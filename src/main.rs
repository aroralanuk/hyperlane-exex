use eyre::Result;
use tracing::debug;
use std::{env, sync::Arc};
use std::{
    future::Future,
    pin::Pin,
    task::{ready, Context, Poll},
};
// use alloy_primitives::{address, Address};
use alloy_sol_types::{sol, SolEventInterface};
use futures_util::{FutureExt, TryStreamExt};
// use ethers::{
//     core::k256::{ecdsa::SigningKey, SecretKey},
//     signers::LocalWallet,
// };
// use hyperlane_core::HyperlaneSignerExt;
// use hyperlane_ethereum::Signers::Local;
use reth_exex::{ExExContext, ExExEvent, ExExNotification};
use reth_node_api::FullNodeComponents;
use reth_node_ethereum::EthereumNode;
use reth_primitives::{Log, SealedBlockWithSenders, TransactionSigned};
use reth_provider::Chain;
use reth_tracing::tracing::info;

// use rusoto_core::Region;


use Mailbox::MailboxEvents;

use crate::Mailbox::{DispatchId, Dispatch};
sol!(Mailbox, "mailbox_abi.json");

mod message;
mod processor;
mod checkpoint;
mod signer;
mod s3_storage;

// mod s3_storage;
// use s3_storage::S3Storage;

// mod checkpoint;
// use checkpoint::{checkpoint_key, MessageIdCheckpoint};

struct HyperlaneExEx<Node: FullNodeComponents> {
    /// The context of the ExEx
    ctx: ExExContext<Node>,
}

impl<Node: FullNodeComponents> HyperlaneExEx<Node> {
    /// Create a new instance of the ExEx
    fn new(ctx: ExExContext<Node>) -> Self {
        Self { ctx }
    }
}

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
        println!("hey!!");
        // Get the secret key from the environment variable "PRIVATE_KEY"
        // let secret_key_str = env::var("PRIVATE_KEY").expect("PRIVATE_KEY environment variable not set");

        // let secret_key =
        //     SecretKey::from_be_bytes(secret_key_str.as_bytes()).expect("Invalid secret key bytes");

        // Create the signer
        // let signer = Local(LocalWallet::from(SigningKey::from(secret_key)));

        // let s3_instance: S3Storage = S3Storage {
        //     bucket: "hyperlane-validator-signatures-ethereum".to_string(), // pick your bucket name here
        //     region: Region::UsEast1,                                       // pick region
        //     authenticated_client: Default::default(), // use your own authenticated client here
        // };

        while let Some(notification) = ready!(this.ctx.notifications.try_next().poll_unpin(cx))? {
            match &notification {
                ExExNotification::ChainCommitted { new } => {
                    let committed_chain = notification.committed_chain().unwrap();
                    info!(committed_chain = ?new.range(), "Received commit");
                    println!("Received commit, {:?}", new.range());

                    let events = decode_chain_into_events(&committed_chain);

                    let mut dispatches = 0;

                    for (block, _, _, event) in events {
                        match event {
                            MailboxEvents::Dispatch(Dispatch { sender, destination, recipient, message }) => {
                                println!("Dispatch: sender: {}, destination: {}, recipient: {}, message: {}", sender, destination, recipient, hex::encode(message));
                            },
                            MailboxEvents::DispatchId(DispatchId { messageId }) => {
                                // let checkpoint = MessageIdCheckpoint {
                                //     message_id: messageId.into(),
                                // };
                                // ecdsa sign the checkpoint
                                // let signed_checkpoint = signer.sign(checkpoint).await.unwrap();
                                // let serialized_checkpoint =
                                //     serde_json::to_string_pretty(&signed_checkpoint)?;

                                // write to bucket
                                // s3_instance
                                //     .write_to_bucket(
                                //         checkpoint_key(checkpoint.message_id),
                                //         &serialized_checkpoint,
                                //     )
                                //     .await
                                //     .map_err(|e| eyre::eyre!("Failed to write to S3: {:?}", e))?;

                                dispatches += 1;
                                println!(
                                    "Added checkpoint #{} with messageId {} to S3 bucket for block #{}",
                                    dispatches, hex::encode(messageId), block.number
                                );
                            },
                            _ => continue,
                        }
                    }
                }
                ExExNotification::ChainReorged { old, new } => {
                    let reverted_chain = notification.reverted_chain().unwrap();
                    info!(reverted_chain = ?old.range(), to_chain = ?new.range(), "Received reorg");

                    // delete_checkpoints_from_s3(&s3_instance, &reverted_chain).await?;
                }
                ExExNotification::ChainReverted { old } => {
                    let reverted_chain = notification.reverted_chain().unwrap();
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

        Poll::Ready(Ok(()))
    }
}

// async fn delete_checkpoints_from_s3(s3_instance: &S3Storage, chain: &Arc<Chain>) -> Result<()> {
//     let events = decode_chain_into_events(chain);

//     for (block, _, _, event) in events {
//         if let MailboxEvents::DispatchId(DispatchId { messageId }) = event {
//             let checkpoint = MessageIdCheckpoint {
//                 message_id: messageId.into(),
//             };
//             // delete from bucket
//             s3_instance
//                 .delete_from_bucket(checkpoint_key(checkpoint.message_id))
//                 .await
//                 .map_err(|e| eyre::eyre!("Failed to delete from S3: {:?}", e))?;
//             info!(
//                 "Deleted checkpoint with messageId {} from S3 bucket for block #{}",
//                 hex::encode(messageId), block.number
//             );
//         }
//     }
//     Ok(())
// }

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
        // Get all logs
        .flat_map(|(block, tx, receipt)| receipt.logs.iter().map(move |log| (block, tx, log)))
        // Decode and filter bridge events
        .filter_map(|(block, tx, log)| {
            MailboxEvents::decode_raw_log(log.topics(), &log.data.data, true)
                .ok()
                .map(|event| (block, tx, log, event))
        })
}

fn main() -> eyre::Result<()> {
    reth::cli::Cli::parse_args().run(|builder, _| async move {
        let handle = builder
            .node(EthereumNode::default())
            .install_exex("hyperlane-exex", |ctx| async move { Ok(HyperlaneExEx::new(ctx)) })
            .launch()
            .await?;

        handle.wait_for_node_exit().await
    })
}


#[cfg(test)]
mod tests {
    use alloy_consensus::TxEip1559;
    use alloy_primitives::{Address, TxKind, FixedBytes};
    use tracing_test::traced_test; 
    
    use reth::revm::db::BundleState;
    use reth_execution_types::{Chain, ExecutionOutcome};
    use reth_exex_test_utils::{test_exex_context, PollOnce};
    use alloy_sol_types::SolEvent;
    use reth_testing_utils::generators::{self, random_block, random_receipt, BlockParams};
    use reth_primitives::{
        Block, BlockBody, Header, Log, Receipt, Transaction, TransactionSigned, TxType,
    };
    use reth_testing_utils::generators::sign_tx_with_random_key_pair;
    use std::pin::pin;

    use crate::Mailbox::{DispatchId, MailboxEvents};

    fn construct_tx_and_receipt<E: SolEvent>(
        to: Address,
        event: E,
    ) -> eyre::Result<(TransactionSigned, Receipt)> {
        let tx = Transaction::Eip1559(TxEip1559 {
            to: TxKind::Call(to),
            ..Default::default()
        });

        let log = Log::new(
            to,
            event.encode_topics().into_iter().map(|topic| topic.0).collect(),
            event.encode_data().into(),
        )
        .ok_or_else(|| eyre::eyre!("failed to encode event"))?;

        let receipt = Receipt {
            tx_type: TxType::Eip1559,
            success: true,
            cumulative_gas_used: 0,
            logs: vec![log],
            ..Default::default()
        };
        Ok((sign_tx_with_random_key_pair(&mut rand::thread_rng(), tx), receipt))
    }

    #[tokio::test]
    // #[traced_test]
    async fn test_exex() -> eyre::Result<()> {
        let rng = &mut generators::rng();

        let (ctx, handle) = test_exex_context().await?;
        let mut exex = pin!(super::HyperlaneExEx::new(ctx));

        // Generate random "from" and "to" addresses for deposit and withdrawal events
        let from_address = Address::random();
        let to_address = Address::random();

        let dispatch_event = DispatchId { messageId: FixedBytes::from_slice(&[0u8; 32]) };
        let (dispatch_tx, dispatch_tx_receipt) = construct_tx_and_receipt(to_address, dispatch_event)?;

        let block = Block {
            header: Header::default(),
            body: BlockBody { transactions: vec![dispatch_tx], .. Default::default() },
        }.seal_slow().seal_with_senders().ok_or_else(|| eyre::eyre!("failed to seal block"))?;

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
        handle.send_notification_chain_committed(chain.clone()).await?;
        // Poll the ExEx once, it will process the notification that we just sent
        exex.poll_once().await?;

        Ok(())
    }
}