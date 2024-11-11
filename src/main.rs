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
use reth_exex::{ExExContext, ExExEvent, ExExNotification};
use reth_node_api::FullNodeComponents;
use reth_node_ethereum::EthereumNode;
use reth_primitives::{Log, SealedBlockWithSenders, TransactionSigned};
use reth_provider::Chain;
use reth_tracing::tracing::info;

use Mailbox::MailboxEvents;

use crate::Mailbox::{DispatchId, Dispatch};
sol!(Mailbox, "mailbox_abi.json");

mod message;
mod processor;
mod checkpoint;
mod signer;
mod s3_storage;

use checkpoint::{Checkpoint, CheckpointWithMessageId};


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

                    let events = decode_chain_into_events(&committed_chain);

                    let processor = Arc::clone(&this.processor);

                    for (_, _, _, event) in events {
                        match event {
                            MailboxEvents::Dispatch(Dispatch { sender, destination, recipient, message }) => {
                                println!("Dispatch: sender: {}, destination: {}, recipient: {}", sender, destination, recipient);

                                let decoded_message = match HyperlaneMessage::decode(&message) {
                                    Ok(msg) => msg,
                                    Err(e) => {
                                        eprintln!("Failed to decode HyperlaneMessage: {:?}", e);
                                        continue;
                                    }
                                };

                                let checkpoint_with_id = CheckpointWithMessageId {
                                    message_id: HyperlaneMessage::id(&message),
                                    checkpoint: Checkpoint {
                                        merkle_tree_hook_address: b256!("00000000000000000000000019dc38aeae620380430c200a6e990d5af5480117"),
                                        mailbox_domain: decoded_message.origin_domain,
                                        root: b256!("0a6765ba86e0fe13c871ab982d54fb637812573c9792c4744b35a34005c70c92"),
                                        index: decoded_message.nonce,
                                    }
                                };


                                let processor = Arc::clone(&this.processor);
                                println!("checking to submit checkpoint");
                                tokio::spawn(async move {
                                    if let Err(e) = processor.submit_checkpoint(checkpoint_with_id).await {
                                    eprintln!("Failed to submit checkpoint: {:?}", e);
                                    }
                                });
                            },
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
        // Instantiate a deterministic signing key for testing
        let private_key_str = env::var("PRIVATE_KEY").expect("PRIVATE_KEY environment variable not set");
        let signing_key = SigningKey::from_slice(&hex::decode(private_key_str.trim_start_matches("0x")).unwrap()).unwrap();
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

        let dispatch_id_event = DispatchId { messageId: b256!("a8cffe04926e2dba26c4770dc627dd8f0a86fc3898b2396bb7a54a08497791d0") };
        let dispatch_event = Dispatch { 
            sender: from_address, 
            destination: 42161, 
            recipient: to_address, message: (&hex!(
                "03000da599000021050000000000000000000000005ed594a8f805bdd36fb1c9f1fc9a9cb94ac954c60000a4b1000000000000000000000000bdea34e4bc7316c6c397f17e6a95966579ba9e1600000000000000000000000096fbe82dc7f08641b7f5524b9874638adfd2796000000000000000000000000000000000000000000000000001301cbf18c600000000000000000000000000000000000000000000"
            )).into()
        };
        
        let dispatch_log = Log::new(
            dest_mailbox,
            dispatch_event.encode_topics().into_iter().map(|topic| topic.0).collect(),
            dispatch_event.encode_data().into(),
        ).ok_or_else(|| eyre::eyre!("failed to encode dispatch event"))?;
        
        let (dispatch_tx, dispatch_tx_receipt) = construct_tx_and_receipt(
            dest_mailbox,
            vec![dispatch_log]
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