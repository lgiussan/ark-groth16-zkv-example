use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

#[derive(Clone, Debug)]
pub struct DummyCircuit<F: PrimeField> {
    pub inputs: Vec<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        for input in self.inputs {
            let _ = cs.new_input_variable(|| Ok(input))?;
        }
        Ok(())
    }
}
