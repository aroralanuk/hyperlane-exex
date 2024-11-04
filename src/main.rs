use eyre::Result;
use std::{env, sync::Arc};
use std::{
    future::Future,
    pin::Pin,
    task::{ready, Context, Poll},
};

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


// use Mailbox::MailboxEvents;

// use crate::Mailbox::DispatchId;
sol!(Mailbox, "mailbox_abi.json");

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

                    // let events = decode_chain_into_events(&committed_chain);

                    let mut dispatches = 0;

                    // for (block, _, _, event) in events {
                    //     match event {
                    //         MailboxEvents::DispatchId(DispatchId { messageId }) => {
                    //             // let checkpoint = MessageIdCheckpoint {
                    //             //     message_id: messageId.into(),
                    //             // };
                    //             // ecdsa sign the checkpoint
                    //             // let signed_checkpoint = signer.sign(checkpoint).await.unwrap();
                    //             // let serialized_checkpoint =
                    //             //     serde_json::to_string_pretty(&signed_checkpoint)?;

                    //             // write to bucket
                    //             // s3_instance
                    //             //     .write_to_bucket(
                    //             //         checkpoint_key(checkpoint.message_id),
                    //             //         &serialized_checkpoint,
                    //             //     )
                    //             //     .await
                    //             //     .map_err(|e| eyre::eyre!("Failed to write to S3: {:?}", e))?;

                    //             dispatches += 1;
                    //             info!(
                    //                 "Added checkpoint #{} with messageId {} to S3 bucket for block #{}",
                    //                 dispatches, hex::encode(messageId), block.number
                    //             );
                    //         }
                    //         _ => continue,
                    //     }
                    // }
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
// fn decode_chain_into_events(
//     chain: &Chain,
// ) -> impl Iterator<
//     Item = (
//         &SealedBlockWithSenders,
//         &TransactionSigned,
//         &Log,
//         MailboxEvents,
//     ),
// > {
//     chain
//         // Get all blocks and receipts
//         .blocks_and_receipts()
//         // Get all receipts
//         .flat_map(|(block, receipts)| {
//             block
//                 .body
//                 .iter()
//                 .zip(receipts.iter().flatten())
//                 .map(move |(tx, receipt)| (block, tx, receipt))
//         })
//         // Get all logs
//         .flat_map(|(block, tx, receipt)| receipt.logs.iter().map(move |log| (block, tx, log)))
//         // Decode and filter bridge events
//         .filter_map(|(block, tx, log)| {
//             MailboxEvents::decode_raw_log(log.topics(), &log.data.data, true)
//                 .ok()
//                 .map(|event| (block, tx, log, event))
//         })
// }

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
    use reth::revm::db::BundleState;
    use reth_execution_types::{Chain, ExecutionOutcome};
    use reth_exex_test_utils::{test_exex_context, PollOnce};
    use reth_testing_utils::generators::{self, random_block, random_receipt, BlockParams};
    use std::pin::pin;

    #[tokio::test]
    async fn test_exex() -> eyre::Result<()> {
        let mut rng = &mut generators::rng();

        let (ctx, handle) = test_exex_context().await?;
        let mut exex = pin!(super::HyperlaneExEx::new(ctx));

        let mut expected_state = ExecutionOutcome::default();

        let block_1 =
            random_block(&mut rng, 0, BlockParams { tx_count: Some(1), ..Default::default() })
                .seal_with_senders()
                .ok_or(eyre::eyre!("failed to recover senders"))?;
        let execution_outcome1 = ExecutionOutcome::new(
            BundleState::default(),
            vec![random_receipt(&mut rng, &block_1.body.transactions[0], None)].into(),
            block_1.number,
            vec![],
        );
        // Extend the expected state with the first block
        expected_state.extend(execution_outcome1.clone());

        // Send a notification to the Execution Extension that the chain with the first block has
        // been committed
        handle
            .send_notification_chain_committed(Chain::new(vec![block_1], execution_outcome1, None))
            .await?;
        exex.poll_once().await?;

        Ok(())
    }
}