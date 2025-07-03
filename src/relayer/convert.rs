use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use serde::{ser::SerializeSeq, Serialize, Serializer};

#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum Curve {
    Bn254,
    Bls12_381,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ProofWithCurve<E: Pairing> {
    pub curve: Curve,
    #[serde(with = "ProofDef")]
    pub proof: Proof<E>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct VerifyingKeyWithCurve<E: Pairing> {
    pub curve: Curve,
    #[serde(with = "HexStringSerializer::<E::G1Affine>")]
    pub alpha_g1: E::G1Affine,
    #[serde(with = "HexStringSerializer::<E::G2Affine>")]
    pub beta_g2: E::G2Affine,
    #[serde(with = "HexStringSerializer::<E::G2Affine>")]
    pub gamma_g2: E::G2Affine,
    #[serde(with = "HexStringSerializer::<E::G2Affine>")]
    pub delta_g2: E::G2Affine,
    #[serde(serialize_with = "HexStringSerializer::<E::G1Affine>::serialize_vec")]
    pub gamma_abc_g1: Vec<E::G1Affine>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PublicInputs<F: PrimeField>(
    #[serde(serialize_with = "HexStringSerializer::<F>::serialize_vec")] pub Vec<F>,
);

impl From<Proof<Bn254>> for ProofWithCurve<Bn254> {
    fn from(proof: Proof<Bn254>) -> Self {
        ProofWithCurve {
            curve: Curve::Bn254,
            proof,
        }
    }
}

impl From<Proof<Bls12_381>> for ProofWithCurve<Bls12_381> {
    fn from(proof: Proof<Bls12_381>) -> Self {
        ProofWithCurve {
            curve: Curve::Bls12_381,
            proof,
        }
    }
}

impl From<VerifyingKey<Bn254>> for VerifyingKeyWithCurve<Bn254> {
    fn from(vk: VerifyingKey<Bn254>) -> Self {
        VerifyingKeyWithCurve {
            curve: Curve::Bn254,
            alpha_g1: vk.alpha_g1,
            beta_g2: vk.beta_g2,
            gamma_g2: vk.gamma_g2,
            delta_g2: vk.delta_g2,
            gamma_abc_g1: vk.gamma_abc_g1,
        }
    }
}

impl From<VerifyingKey<Bls12_381>> for VerifyingKeyWithCurve<Bls12_381> {
    fn from(vk: VerifyingKey<Bls12_381>) -> Self {
        VerifyingKeyWithCurve {
            curve: Curve::Bls12_381,
            alpha_g1: vk.alpha_g1,
            beta_g2: vk.beta_g2,
            gamma_g2: vk.gamma_g2,
            delta_g2: vk.delta_g2,
            gamma_abc_g1: vk.gamma_abc_g1,
        }
    }
}

struct HexWrapper<'a, T>(pub &'a T);

impl<T> Serialize for HexWrapper<'_, T>
where
    T: CanonicalSerialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        HexStringSerializer::<T>::serialize(&self.0, serializer)
    }
}

#[derive(Serialize)]
#[serde(remote = "Proof")]
struct ProofDef<E: Pairing> {
    #[serde(with = "HexStringSerializer::<E::G1Affine>")]
    pub a: E::G1Affine,
    #[serde(with = "HexStringSerializer::<E::G2Affine>")]
    pub b: E::G2Affine,
    #[serde(with = "HexStringSerializer::<E::G1Affine>")]
    pub c: E::G1Affine,
}

struct HexStringSerializer<T> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T: CanonicalSerialize> HexStringSerializer<T> {
    pub fn serialize<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut buffer = vec![0; value.uncompressed_size()];
        value
            .serialize_uncompressed(&mut buffer[..])
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&format!("0x{}", &hex::encode(buffer).as_str()))
    }

    pub fn serialize_vec<S>(value: &Vec<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(value.len()))?;
        for v in value {
            seq.serialize_element(&HexWrapper(v))?;
        }
        seq.end()
    }
}
