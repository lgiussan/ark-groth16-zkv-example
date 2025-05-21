use crate::zkverify::runtime_types::hp_groth16::data_structures::{G1, G2, Proof, Scalar};
use crate::zkverify::runtime_types::pallet_groth16_verifier::groth16::{
    Curve, ProofWithCurve, VerificationKeyWithCurve,
};
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

pub trait IntoSubxtProof {
    fn into_subxt_proof(self) -> ProofWithCurve;
}

impl IntoSubxtProof for ark_groth16::Proof<ark_bn254::Bn254> {
    fn into_subxt_proof(self) -> ProofWithCurve {
        ProofWithCurve {
            curve: Curve::Bn254,
            proof: Proof {
                a: self.a.into_g1(),
                b: self.b.into_g2(),
                c: self.c.into_g1(),
            },
        }
    }
}

impl IntoSubxtProof for ark_groth16::Proof<ark_bls12_381::Bls12_381> {
    fn into_subxt_proof(self) -> ProofWithCurve {
        ProofWithCurve {
            curve: Curve::Bls12_381,
            proof: Proof {
                a: self.a.into_g1(),
                b: self.b.into_g2(),
                c: self.c.into_g1(),
            },
        }
    }
}

pub trait IntoSubxtVk {
    fn into_subxt_vk(self) -> VerificationKeyWithCurve;
}

impl IntoSubxtVk for ark_groth16::VerifyingKey<ark_bn254::Bn254> {
    fn into_subxt_vk(self) -> VerificationKeyWithCurve {
        VerificationKeyWithCurve {
            curve: Curve::Bn254,
            alpha_g1: self.alpha_g1.into_g1(),
            beta_g2: self.beta_g2.into_g2(),
            gamma_g2: self.gamma_g2.into_g2(),
            delta_g2: self.delta_g2.into_g2(),
            gamma_abc_g1: self.gamma_abc_g1.iter().map(|g1| g1.into_g1()).collect(),
        }
    }
}

impl IntoSubxtVk for ark_groth16::VerifyingKey<ark_bls12_381::Bls12_381> {
    fn into_subxt_vk(self) -> VerificationKeyWithCurve {
        VerificationKeyWithCurve {
            curve: Curve::Bls12_381,
            alpha_g1: self.alpha_g1.into_g1(),
            beta_g2: self.beta_g2.into_g2(),
            gamma_g2: self.gamma_g2.into_g2(),
            delta_g2: self.delta_g2.into_g2(),
            gamma_abc_g1: self.gamma_abc_g1.iter().map(|g1| g1.into_g1()).collect(),
        }
    }
}

pub trait IntoSubxtScalar {
    fn into_subxt_scalar(self) -> Scalar;
}

impl<F: PrimeField> IntoSubxtScalar for F {
    fn into_subxt_scalar(self) -> Scalar {
        let mut result = Scalar(vec![0; self.uncompressed_size()]);
        self.serialize_uncompressed(&mut result.0[..]).unwrap();
        result
    }
}

trait IntoG1 {
    fn into_g1(self) -> G1;
}

impl<P: SWCurveConfig> IntoG1 for Affine<P> {
    fn into_g1(self) -> G1 {
        let mut result = G1(vec![0; self.uncompressed_size()]);
        self.serialize_uncompressed(&mut result.0[..]).unwrap();
        result
    }
}

trait IntoG2 {
    fn into_g2(self) -> G2;
}

impl<P: SWCurveConfig> IntoG2 for Affine<P> {
    fn into_g2(self) -> G2 {
        let mut result = G2(vec![0; self.uncompressed_size()]);
        self.serialize_uncompressed(&mut result.0[..]).unwrap();
        result
    }
}
