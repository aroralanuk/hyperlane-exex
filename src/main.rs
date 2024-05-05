use futures::Future;

use reth_exex::{ExExContext, ExExEvent, ExExNotification};
use reth_node_api::FullNodeComponents;
use reth_node_ethereum::EthereumNode;
use reth_tracing::tracing::info;
use reth_provider::Chain;
use reth_primitives::{Log, SealedBlockWithSenders, TransactionSigned, keccak256};
use ethers::{core::k256::ecdsa::SigningKey, signers::LocalWallet};
use alloy_sol_types::{sol, SolEventInterface};
use Mailbox::MailboxEvents;
use hyperlane_core::{HyperlaneSignerExt, Signable, SignedType, H256};
use hyperlane_ethereum::Signers::Local;
use serde::{Deserialize, Serialize};

use crate::Mailbox::DispatchId;
sol!(Mailbox, "mailbox_abi.json");


#[derive(Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct MessageIdCheckpoint {
    pub message_id: [u8; 32],
}


pub type SignedMessageIdCheckpoint = SignedType<MessageIdCheckpoint>;

impl Signable for MessageIdCheckpoint {
    fn signing_hash(&self) -> H256 {
        self.message_id.into()
    }
}


/// The initialization logic of the ExEx is just an async function.
///
/// During initialization you can wait for resources you need to be up for the ExEx to function,
/// like a database connection.
async fn exex_init<Node: FullNodeComponents>(
    ctx: ExExContext<Node>,
) -> eyre::Result<impl Future<Output = eyre::Result<()>>> {
    Ok(exex(ctx))
}

/// An ExEx is just a future, which means you can implement all of it in an async function!
///
/// This ExEx just prints out whenever either a new chain of blocks being added, or a chain of
/// blocks being re-orged. After processing the chain, emits an [ExExEvent::FinishedHeight] event.
async fn exex<Node: FullNodeComponents>(mut ctx: ExExContext<Node>) -> eyre::Result<()> {
    while let Some(notification) = ctx.notifications.recv().await {
        match &notification {
            ExExNotification::ChainCommitted { new } => {
                let committed_chain = notification.committed_chain().unwrap();
                info!(committed_chain = ?new.range(), "Received commit");

                let events = decode_chain_into_events(&committed_chain);

                let mut dispatches = 0;

                for (block, tx, log, event) in events {
                    match event {
                        MailboxEvents::DispatchId(DispatchId {
                            messageId
                        }) => {
                            let key = SigningKey::from_bytes(&[0; 32]).unwrap();
                            let signer = Local(LocalWallet::from(
                                ethers::core::k256::ecdsa::SigningKey::from(
                                    ethers::core::k256::SecretKey::from_be_bytes(&[0; 32]).unwrap(),
                                ),
                            ));
                            let signed_checkpoint = signer.sign(MessageIdCheckpoint { message_id: messageId.into() }).await.unwrap();
                            let serialized_checkpoint = serde_json::to_string_pretty(&signed_checkpoint)?;
                            // write to bucket
                            dispatches += 1;
                        }
                        _ => continue,
                    }
                };

            }
            ExExNotification::ChainReorged { old, new } => {
                info!(from_chain = ?old.range(), to_chain = ?new.range(), "Received reorg");
            }
            ExExNotification::ChainReverted { old } => {
                info!(reverted_chain = ?old.range(), "Received revert");
            }
        };

        if let Some(committed_chain) = notification.committed_chain() {
            ctx.events.send(ExExEvent::FinishedHeight(committed_chain.tip().number))?;
        }
    }
    Ok(())
}

/// Decode chain of blocks into a flattened list of receipt logs, and filter only
/// [L1StandardBridgeEvents].
fn decode_chain_into_events(
    chain: &Chain,
) -> impl Iterator<Item = (&SealedBlockWithSenders, &TransactionSigned, &Log, MailboxEvents)>
{
    chain
        // Get all blocks and receipts
        .blocks_and_receipts()
        // Get all receipts
        .flat_map(|(block, receipts)| {
            block
                .body
                .iter()
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
            .install_exex("Minimal", exex_init)
            .launch()
            .await?;

        handle.wait_for_node_exit().await
    })
}
