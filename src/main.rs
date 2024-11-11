use alloy_primitives::{b256, Address};
use eyre::Result;
use k256::ecdsa::SigningKey;
use message::HyperlaneMessage;
use processor::{Processor, S3Processor};
use s3_storage::S3Storage;
use signer::PrivateKeySigner;
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

use checkpoint::{Checkpoint, CheckpointWithMessageId};

// mod s3_storage;
// use s3_storage::S3Storage;

// mod checkpoint;
// use checkpoint::{checkpoint_key, MessageIdCheckpoint};

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

        while let Some(notification) = ready!(this.ctx.notifications.try_next().poll_unpin(cx))? {
            match &notification {
                ExExNotification::ChainCommitted { new } => {
                    let committed_chain = notification.committed_chain().unwrap();
                    info!(committed_chain = ?new.range(), "Received commit");
                    println!("Received commit, {:?}", new.range());

                    let events = decode_chain_into_events(&committed_chain);

                    let mut dispatches = 0;

                    for (block, _, _, event) in events {
                        let mut message_index = 0;
                        let mut mailbox_origin = 0;
                        let mut message_id = b256!("0000000000000000000000000000000000000000000000000000000000000000");
                        match event {
                            MailboxEvents::Dispatch(Dispatch { sender, destination, recipient, message }) => {
                                println!("Dispatch: sender: {}, destination: {}, recipient: {}", sender, destination, recipient);
                                message_index = HyperlaneMessage::decode(&message.clone()).unwrap().nonce;
                                mailbox_origin = HyperlaneMessage::decode(&message).unwrap().origin_domain;
                            },
                            MailboxEvents::DispatchId(DispatchId { messageId }) => {

                                message_id = messageId;
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
                            _ => {}
                        }

                        let checkpoint_with_id = CheckpointWithMessageId {
                            message_id: message_id,
                            checkpoint: Checkpoint {
                                merkle_tree_hook_address: b256!("00000000000000000000000019dc38aeae620380430c200a6e990d5af5480117"),
                                mailbox_domain: mailbox_origin,
                                root: b256!("f4c3496c966c086cf403aa90d7a76cd2b9a6e4a231a995a46f52602132363367"),
                                index: message_index,
                            }
                        };

                        let processor = Arc::clone(&this.processor);
                        println!("checking to submit checkpoint");
                        tokio::spawn(async move {
                            if let Err(e) = processor.submit_checkpoint(checkpoint_with_id).await {
                                eprintln!("Failed to submit checkpoint: {:?}", e);
                            }
                        });




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
            // Initialize the signer
        let private_key_str = env::var("PRIVATE_KEY").expect("PRIVATE_KEY environment variable not set");
        let private_key_bytes = hex::decode(private_key_str.trim_start_matches("0x"))?;
        let signing_key = SigningKey::from_slice(&private_key_bytes)
            .map_err(|_| eyre::eyre!("Invalid private key format"))?;
        let signer = Arc::new(PrivateKeySigner::new(signing_key));

        let s3_instance = Arc::new(S3Storage::new(
            "hyperlane-validator-signatures-ethereum".to_string(), 
            rusoto_core::Region::UsEast1,                           
        ));
        
        let processor = Arc::new(S3Processor::new(signer, s3_instance));

        let handle = builder
            .node(EthereumNode::default())
            .install_exex("hyperlane-exex", |ctx| async move { Ok(HyperlaneExEx::new(ctx, processor)) })
            .launch()
            .await?;

        handle.wait_for_node_exit().await
    })
}


#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::TxEip1559;
    use alloy_primitives::{address, Address, FixedBytes, TxKind};
    use rand::rngs::OsRng;
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
    use alloy_primitives::hex;

    use crate::Mailbox::{DispatchId, Dispatch, MailboxEvents};
    

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
        Ok((sign_tx_with_random_key_pair(&mut rand::thread_rng(), tx), receipt))
    }

    #[tokio::test]
    // #[traced_test]
    async fn test_exex() -> eyre::Result<()> {
        let rng = &mut generators::rng();

        // Instantiate a deterministic signing key for testing
        let signing_key = SigningKey::from_slice(&hex::decode("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap()).unwrap();
        let signer = Arc::new(PrivateKeySigner::new(signing_key));

        // Instantiate a mock or in-memory S3Storage for testing
        let s3_instance = Arc::new(S3Storage::new(
            "test-bucket".to_string(),
            rusoto_core::Region::UsEast1,
        ));
        let processor = Arc::new(S3Processor::new(signer, s3_instance));

        let (ctx, handle) = test_exex_context().await?;
        let mut exex = pin!(HyperlaneExEx::new(ctx, processor));

        // Generate random "from" and "to" addresses for deposit and withdrawal events
        let from_address = Address::random();
        let dest_mailbox = address!("d4C1905BB1D26BC93DAC913e13CaCC278CdCC80D");
        let to_address = b256!("000000000000000000000000acEB607CdF59EB8022Cc0699eEF3eCF246d149e2");

        let dispatch_id_event = DispatchId { messageId: FixedBytes::from_slice(&[0u8; 32]) };
        let dispatch_event = Dispatch { 
            sender: from_address, 
            destination: 42161, 
            recipient: to_address, message: (&hex!(
                "03000d9a51000021050000000000000000000000002552516453368e42705d791f674b312b8b87cd9e0000000a000000000000000000000000aceb607cdf59eb8022cc0699eef3ecf246d149e20000000000000000000000002ae5fdab940cccfafbc4eccd34345503912ec69d00000000000000000000000000000000000000000000000006c53613ec96a792"
            )).into()
        };
        let dispatch_id_log = Log::new(
            dest_mailbox,
            dispatch_id_event.encode_topics().into_iter().map(|topic| topic.0).collect(),
            dispatch_id_event.encode_data().into(),
        ).ok_or_else(|| eyre::eyre!("failed to encode dispatch_id event"))?;
        
        let dispatch_log = Log::new(
            dest_mailbox,
            dispatch_event.encode_topics().into_iter().map(|topic| topic.0).collect(),
            dispatch_event.encode_data().into(),
        ).ok_or_else(|| eyre::eyre!("failed to encode dispatch event"))?;
        
        let (dispatch_tx, dispatch_tx_receipt) = construct_tx_and_receipt(
            dest_mailbox,
            vec![dispatch_id_log, dispatch_log]
        )?;

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

        // tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
        // Await all pending tasks in the runtime
        tokio::task::yield_now().await;

        Ok(())
    }
}