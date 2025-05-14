use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_snark::SNARK;
use ark_std::UniformRand;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use subxt::{OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::dev;
use zkverify::settlement_groth16_pallet::calls::types::submit_proof::VkOrHash;

mod circuit;
pub mod convert;

use circuit::*;
use convert::{IntoSubxtProof, IntoSubxtScalar, IntoSubxtVk};

// Generate an interface that we can use from the node's metadata.
#[subxt::subxt(runtime_metadata_path = "./zkverify-metadata.scale")]
pub mod zkverify {}

#[tokio::main]
async fn main() {
    main_impl::<Bn254>().await;
}

async fn main_impl<E>()
where
    E: Pairing,
    ark_groth16::Proof<E>: IntoSubxtProof,
    ark_groth16::VerifyingKey<E>: IntoSubxtVk,
{
    // Build vk, proof, and public inputs with `ark_groth16` library
    let num_inputs = 3;
    let rng = &mut StdRng::seed_from_u64(0);

    let circuit = DummyCircuit {
        inputs: (0..num_inputs).map(|_| E::ScalarField::rand(rng)).collect(),
    };

    let (pk, vk) = ark_groth16::Groth16::<E>::circuit_specific_setup(circuit.clone(), rng).unwrap();
    let proof = ark_groth16::Groth16::<E>::prove(&pk, circuit.clone(), rng).unwrap();
    ark_groth16::Groth16::<E>::verify(&vk, circuit.inputs.as_slice(), &proof).unwrap();

    // Convert to subxt types
    let vk = vk.into_subxt_vk();
    let proof = proof.into_subxt_proof();
    let inputs: Vec<_> = circuit
        .inputs
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
    let api = OnlineClient::<PolkadotConfig>::new().await.unwrap();

    api.tx()
        .sign_and_submit_then_watch_default(&submit_proof_tx, &dev::alice())
        .await
        .unwrap()
        .wait_for_finalized_success()
        .await
        .unwrap();
}
