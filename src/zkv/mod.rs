use ark_ec::pairing::Pairing;
use std::env;
use subxt::{OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::dev;
use subxt_signer::{bip39::Mnemonic, sr25519::Keypair};
use zkverify::settlement_groth16_pallet::calls::types::submit_proof::VkOrHash;

// Generate an interface that we can use from the node's metadata.
#[subxt::subxt(runtime_metadata_path = "./zkverify-metadata.scale")]
pub mod zkverify {}

mod convert;
pub use convert::{IntoSubxtProof, IntoSubxtScalar, IntoSubxtVk};

pub async fn send_proof_to_zkv<E>(
    vk: ark_groth16::VerifyingKey<E>,
    proof: ark_groth16::Proof<E>,
    inputs: Vec<E::ScalarField>,
    zkv_url: &str,
) where
    E: Pairing,
    ark_groth16::Proof<E>: IntoSubxtProof,
    ark_groth16::VerifyingKey<E>: IntoSubxtVk,
{
    // Convert to subxt types
    let vk = vk.into_subxt_vk();
    let proof = proof.into_subxt_proof();
    let inputs: Vec<_> = inputs
        .into_iter()
        .map(IntoSubxtScalar::into_subxt_scalar)
        .collect();

    // Build proof verification transaction
    let submit_proof_tx = zkverify::tx().settlement_groth16_pallet().submit_proof(
        VkOrHash::Vk(vk.into()),
        proof,
        inputs,
        None,
    );

    // Submit transaction to zkVerify
    let key_pair = env::var("ZKV_SECRET_PHRASE")
        .map(|phrase| Mnemonic::parse(phrase).unwrap())
        .map(|mnemonic| Keypair::from_phrase(&mnemonic, None).unwrap())
        .unwrap_or(dev::alice());

    let api = OnlineClient::<PolkadotConfig>::from_url(&zkv_url)
        .await
        .unwrap();

    let result = api
        .tx()
        .sign_and_submit_then_watch_default(&submit_proof_tx, &key_pair)
        .await
        .unwrap()
        .wait_for_finalized_success()
        .await
        .unwrap();

    println!(
        "Transaction finalized on zkVerify, tx hash: {:?}",
        result.extrinsic_hash()
    )
}
