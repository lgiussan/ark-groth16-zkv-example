use crate::zkverify::runtime_types::hp_groth16::data_structures::Scalar;
use crate::zkverify::runtime_types::pallet_groth16_verifier::groth16::{
    ProofWithCurve, VerificationKeyWithCurve,
};
use ark_ff::PrimeField;
use subxt::ext::codec::{Decode, Encode};

pub trait IntoSubxtProof {
    fn into_subxt_proof(self) -> ProofWithCurve;
}

impl IntoSubxtProof for ark_groth16::Proof<ark_bn254::Bn254> {
    fn into_subxt_proof(self) -> ProofWithCurve {
        pallet_groth16_verifier::Proof::new(
            pallet_groth16_verifier::Curve::Bn254,
            self.try_into().unwrap(),
        )
        .try_encode_decode()
        .unwrap()
    }
}

impl IntoSubxtProof for ark_groth16::Proof<ark_bls12_381::Bls12_381> {
    fn into_subxt_proof(self) -> ProofWithCurve {
        pallet_groth16_verifier::Proof::new(
            pallet_groth16_verifier::Curve::Bls12_381,
            self.try_into().unwrap(),
        )
        .try_encode_decode()
        .unwrap()
    }
}

pub trait IntoSubxtVk {
    fn into_subxt_vk(self) -> VerificationKeyWithCurve;
}

impl IntoSubxtVk for ark_groth16::VerifyingKey<ark_bn254::Bn254> {
    fn into_subxt_vk(self) -> VerificationKeyWithCurve {
        pallet_groth16_verifier::Vk::from_curve_and_vk(
            pallet_groth16_verifier::Curve::Bn254,
            self.try_into().unwrap(),
        )
        .try_encode_decode()
        .unwrap()
    }
}

impl IntoSubxtVk for ark_groth16::VerifyingKey<ark_bls12_381::Bls12_381> {
    fn into_subxt_vk(self) -> VerificationKeyWithCurve {
        pallet_groth16_verifier::Vk::from_curve_and_vk(
            pallet_groth16_verifier::Curve::Bls12_381,
            self.try_into().unwrap(),
        )
        .try_encode_decode()
        .unwrap()
    }
}

pub trait IntoSubxtScalar {
    fn into_subxt_scalar(self) -> Scalar;
}

impl<F: PrimeField> IntoSubxtScalar for F {
    fn into_subxt_scalar(self) -> Scalar {
        hp_groth16::Scalar::try_from_scalar(self)
            .unwrap()
            .try_encode_decode()
            .unwrap()
    }
}

trait TryEncodeDecode: Encode {
    fn try_encode_decode<D: Decode>(&self) -> Result<D, parity_scale_codec::Error> {
        Decode::decode(&mut self.encode().as_slice())
    }
}

impl<T: Encode> TryEncodeDecode for T {}
