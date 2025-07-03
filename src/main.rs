use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_snark::SNARK;
use ark_std::UniformRand;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use clap::{Parser, Subcommand, ValueEnum};

mod circuit;
pub mod relayer;
pub mod zkv;

use circuit::*;
use zkv::{IntoSubxtProof, IntoSubxtVk};

#[derive(Debug, Copy, Clone, ValueEnum, Default)]
pub enum Curve {
    #[default]
    Bn254,
    Bls12_381,
}

/// Simple program to generate a groth16 proof and submit it to zkVerify
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate and send a Groth16 proof to zkVerify blockchain
    SendToZkv {
        /// Url of zkVerify rpc node
        #[arg(long, default_value_t = String::from("ws://127.0.0.1:9944"))]
        url: String,

        /// Number of public inputs of the circuit
        #[arg(short, long, default_value_t = 1)]
        num_inputs: u32,

        /// SNARK curve
        #[arg(short, long, default_value_t, value_enum)]
        curve: Curve,
    },
    SendToRelayer {
        /// Url of zkVerify relayer
        #[arg(long, default_value_t = String::from("https://relayer-api.horizenlabs.io/api/v1"))]
        url: String,

        /// Number of public inputs of the circuit
        #[arg(short, long, default_value_t = 1)]
        num_inputs: u32,

        /// SNARK curve
        #[arg(short, long, default_value_t, value_enum)]
        curve: Curve,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::SendToZkv {
            url,
            num_inputs,
            curve,
        } => match curve {
            Curve::Bn254 => generate_and_send_proof_to_zkv::<Bn254>(num_inputs, &url).await,
            Curve::Bls12_381 => generate_and_send_proof_to_zkv::<Bls12_381>(num_inputs, &url).await,
        },
        Commands::SendToRelayer {
            url,
            num_inputs,
            curve,
        } => match curve {
            Curve::Bn254 => generate_and_send_proof_to_relayer::<Bn254>(num_inputs, &url).await,
            Curve::Bls12_381 => {
                generate_and_send_proof_to_relayer::<Bls12_381>(num_inputs, &url).await
            }
        },
    }
}

async fn generate_and_send_proof_to_zkv<E: Pairing>(num_inputs: u32, zkv_url: &str)
where
    E: Pairing,
    ark_groth16::Proof<E>: IntoSubxtProof,
    ark_groth16::VerifyingKey<E>: IntoSubxtVk,
{
    let (vk, proof, inputs) = generate_proving_artifacts::<E>(num_inputs);
    zkv::send_proof_to_zkv(vk, proof, inputs, zkv_url).await;
}

async fn generate_and_send_proof_to_relayer<E: Pairing>(num_inputs: u32, zkv_url: &str)
where
    E: Pairing,
    ark_groth16::Proof<E>: Into<relayer::ProofWithCurve<E>>,
    ark_groth16::VerifyingKey<E>: Into<relayer::VerifyingKeyWithCurve<E>>,
{
    let (vk, proof, inputs) = generate_proving_artifacts::<E>(num_inputs);
    relayer::send_proof_to_relayer(vk, proof, inputs, zkv_url).await;
}

fn generate_proving_artifacts<E: Pairing>(
    num_inputs: u32,
) -> (
    ark_groth16::VerifyingKey<E>,
    ark_groth16::Proof<E>,
    Vec<E::ScalarField>,
) {
    let rng = &mut StdRng::seed_from_u64(0);

    let inputs: Vec<_> = (0..num_inputs).map(|_| E::ScalarField::rand(rng)).collect();
    let circuit = DummyCircuit {
        inputs: inputs.clone(),
    };

    let (pk, vk) = ark_groth16::Groth16::<E>::circuit_specific_setup(circuit.clone(), rng).unwrap();
    let proof = ark_groth16::Groth16::<E>::prove(&pk, circuit.clone(), rng).unwrap();

    (vk, proof, inputs)
}
