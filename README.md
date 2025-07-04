# ark-groth16-zkv-example

A simple example of submission of Groth16 proofs generated with [`ark-groth16`](https://github.com/arkworks-rs/groth16) library to zkVerify chain in two possible ways:

- directly, via [`subxt`](https://github.com/paritytech/subxt) library (requires having test tVFY tokens)
- indirectly, via the [`Relayer`](https://docs.zkverify.io/overview/getting-started/relayer) service (doesn't require tVFY tokens)

## Overview

The example demonstrates how to:

1. Generate a Groth16 proof with `ark-groth16` library.
2. Convert the generated artifacts into `subxt` datatypes.
3. Send a `submit_proof` extrinsic to zkVerify `pallet_settlement_groth16` to have the proof verified on zkVerify.

## Prerequisites

The program can be used to submit proof both to a local development zkVerify node, and to the actual zkVerify testnet.
In the first case, instructions to locally run a node in development mode can be found inside [zkVerify documentation](https://github.com/zkVerify/zkVerify?tab=readme-ov-file#run-dev-node).
In the second case, you need to acquire some testnet tVFY tokens (e.g. using this [faucet](https://www.faucy.com/zkverify-volta)).

## Downloading zkVerify SCALE metadata

`subxt` library uses SCALE metadata of the target chain to build a typed interface to interact with that chain. ZkVerify metadata are already committed in the repo here. They can be downloaded by [installing `subxt-cli`](https://github.com/paritytech/subxt?tab=readme-ov-file#downloading-metadata-from-a-substrate-node) and running the command

```bash
subxt metadata \
  --pallets="SettlementGroth16Pallet" \
  --runtime-apis="" \
  --format="bytes" \
  --url="https://volta-rpc.zkverify.io" \
  --output-file="zkverify-metadata.scale"
```

## Build instructions

1. Clone the repository:

   ```bash
   git clone https://github.com/lgiussan/ark-groth16-zkv-example.git
   cd ark-groth16-zkv-example
   ```

2. Build the project:

   ```bash
   cargo build --release
   ```

## Usage

There are three options for submitting proofs to zkVerify. All the following commands allow to specify the number of inputs (from 0 to 64) via the optional parameter `--num-inputs` (default is 1), and the curve (`bn254`, or `bls12-381`) via the optional parameter `--curve` (default is `bn254`).

### Submitting proofs to local development zkVerify node

By default, the `send-to-zkv` command connects to a local instance of zkVerify running at `127.0.0.1:9944` and uses the pre-funded development `alice` account

```bash
./target/release/ark-groth16-zkv-example send-to-zkv
```

### Submitting proofs to actual zkVerify testnet

Otherwise, if you want to send proofs to the real zkVerify testnet, you should set the `ZKV_SERET_PHRASE` to the secret phrase of your zkVerify testnet account, and specify the rpc endpoint url, like this:

```bash
ZKV_SECRET_PHRASE="bottom drive obey lake curtain smoke basket hold race lonely fit walk" \
    ./target/release/ark-groth16-zkv-example send-to-zkv --url="wss://volta-rpc.zkverify.io"
```

### Submitting proofs via the relayer

A third option is to send proofs via the relayer service

```bash
RELAYER_API_KEY=<your-api-key> ./target/release/ark-groth16-zkv-example send-to-relayer
```
