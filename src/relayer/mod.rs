mod convert;

use std::env;

use ark_ec::pairing::Pairing;
use convert::Curve;
pub use convert::{ProofWithCurve, PublicInputs, VerifyingKeyWithCurve};
use serde::Deserialize;
use serde_json::json;

pub async fn send_proof_to_relayer<E>(
    vk: ark_groth16::VerifyingKey<E>,
    proof: ark_groth16::Proof<E>,
    inputs: Vec<E::ScalarField>,
    zkv_url: &str,
) where
    E: Pairing,
    ark_groth16::Proof<E>: Into<ProofWithCurve<E>>,
    ark_groth16::VerifyingKey<E>: Into<VerifyingKeyWithCurve<E>>,
{
    let client = reqwest::Client::new();
    let api_key = env::var("RELAYER_API_KEY").unwrap();
    let url = format!("{zkv_url}/submit-proof/{api_key}");

    let proof_with_curve: ProofWithCurve<E> = proof.into();
    let vk_with_curve: VerifyingKeyWithCurve<E> = vk.into();
    let inputs = PublicInputs(inputs);
    let curve = match proof_with_curve.curve {
        Curve::Bn254 => "bn128",
        Curve::Bls12_381 => "bls12381",
    };

    let body = json!({
        "proofType": "groth16",
        "vkRegistered": false,
        "proofOptions": {
            "library": "arkworks",
            "curve": curve,
        },
        "proofData": {
            "proof": proof_with_curve,
            "vk": vk_with_curve,
            "publicSignals": inputs,
        }
    });

    let res = client.post(url).json(&body).send().await.unwrap();

    let RelayerResponse {
        job_id,
        optimistic_verify,
    } = res.json().await.unwrap();
    if optimistic_verify == "success" {
        println!("proof optimistically verified, jobId {job_id}");
    } else {
        println!("proof verification failed, jobId {job_id}");
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayerResponse {
    pub job_id: String,
    pub optimistic_verify: String,
}
