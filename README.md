# Hyperlane ExEx (old)

PoC of a hyperlane [validator](https://docs.hyperlane.xyz/docs/protocol/agents/validators) built on top of Reth's new ExEx framework for post execution hooks. See more details about ExEx [here](https://www.paradigm.xyz/2024/05/reth-exex).

### Introduction

![Hyperlane ExEx ETL](./assets/hyperlane-exex.png)

A bit of background on hyperlane's validators: validators are super lightweight off-chain agents which sign the hyperlane messages (either just the messageId as shown in the example, or by first building the incremental merkle tree and then signing the root which is currently live in production) from a source chain which gets verified on destination by the respective [InterchainSecurityModule](https://docs.hyperlane.xyz/docs/reference/ISM/specify-your-ISM) contracts.

This can be easily transformed into a ETL pipeline as pictured:

- observe Mailbox (or MerkleTreeHook) dispatch events from the node state
- signed the derived messageId with the EIP-191 standard scheme
- post the signed payload to a openly available datastore (s3 bucket in our case)

Please note that only the simpler mailbox ExEx has been built so far. This is just a simple example and not ready for production use.

### Setup

// TODO

### Tests

// TODO
