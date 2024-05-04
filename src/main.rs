use futures::Future;
use reth_exex::{ExExContext, ExExEvent, ExExNotification};
use reth_node_api::FullNodeComponents;
use reth_node_ethereum::EthereumNode;
use reth_tracing::tracing::info;
use reth_provider::Chain;
use reth_primitives::{Log, SealedBlockWithSenders, TransactionSigned, keccak256};

use alloy_sol_types::{sol, SolEventInterface};
use Mailbox::MailboxEvents;

use crate::Mailbox::DispatchId;
sol!(Mailbox, "mailbox_abi.json");

use secp256k1::{
    ecdsa::RecoverableSignature,
    SecretKey, SECP256K1
};


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
                            dispatches += 1;
                            
                            let secret_key = SecretKey::from_slice(&[0u8; 32]).unwrap();
                            let signature: RecoverableSignature = SECP256K1.sign_ecdsa_recoverable(
                                &secp256k1::Message::from_digest(keccak256(&messageId).0),
                                &secret_key,
                            );
                            // write signature to bucket

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
