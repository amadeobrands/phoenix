use crate::{BlsScalar, TransactionInput, TransactionItem, TransactionOutput};

use dusk_plonk::constraint_system::{StandardComposer, Variable};

/// Prove that the amount inputted equals the amount outputted.
/// This gadget adds constraints for each input value, and each output value.
/// The remaining value is then returned as a [`Variable`], which the caller can
/// constrain to zero at their own discretion. The reason we don't do it inside of
/// the gadget, is because there are different scenarios in which a rest value needs
/// to be constrained before constraining the entire sum to zero, and each case does
/// it slightly differently.
pub fn balance(
    composer: &mut StandardComposer,
    inputs: &[TransactionInput],
    outputs: &[TransactionOutput],
) -> Variable {
    let mut sum = composer.zero_var;
    for item in inputs.iter() {
        let value = composer.add_input(BlsScalar::from(item.value()));
        sum = composer.add(
            (BlsScalar::one(), sum),
            (BlsScalar::one(), value),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
    }

    for item in outputs.iter() {
        let value = composer.add_input(BlsScalar::from(item.value()));
        sum = composer.add(
            (BlsScalar::one(), sum),
            (-BlsScalar::one(), value),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
    }

    sum
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto, Note, NoteGenerator, SecretKey, Transaction, TransactionOutput, TransparentNote,
    };
    use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
    use dusk_plonk::fft::EvaluationDomain;
    use merlin::Transcript;

    #[test]
    fn balance_gadget() {
        let mut tx = Transaction::default();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 100;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        tx.push_input(note.to_transaction_input(merkle_opening, sk).unwrap())
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 95;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 2;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 3;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.set_fee(note.to_transaction_output(value, blinding_factor, pk));

        let mut composer = StandardComposer::new();

        let mut outputs: Vec<TransactionOutput> = vec![];
        tx.outputs().iter().for_each(|output| {
            outputs.push(*output);
        });
        outputs.push(*tx.fee());
        balance(&mut composer, tx.inputs(), &outputs);

        composer.add_dummy_constraints();

        // Generate Composer & Public Parameters
        let pub_params = PublicParameters::setup(1 << 17, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = pub_params.trim(1 << 16).unwrap();
        let mut transcript = Transcript::new(b"TEST");

        let circuit = composer.preprocess(
            &ck,
            &mut transcript,
            &EvaluationDomain::new(composer.circuit_size()).unwrap(),
        );

        let proof = composer.prove(&ck, &circuit, &mut transcript.clone());

        assert!(proof.verify(&circuit, &mut transcript, &vk, &composer.public_inputs()));
    }

    #[test]
    #[ignore]
    fn tx_balance_invalid() {
        let mut tx = Transaction::default();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 100;
        let note = TransparentNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        tx.push_input(note.to_transaction_input(merkle_opening, sk).unwrap())
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 95;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 100;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 3;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.set_fee(note.to_transaction_output(value, blinding_factor, pk));

        let mut composer = StandardComposer::new();

        let mut outputs: Vec<TransactionOutput> = vec![];
        tx.outputs().iter().for_each(|output| {
            outputs.push(*output);
        });
        outputs.push(*tx.fee());
        balance(&mut composer, tx.inputs(), &outputs);

        composer.add_dummy_constraints();

        // Generate Composer & Public Parameters
        let pub_params = PublicParameters::setup(1 << 17, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = pub_params.trim(1 << 16).unwrap();
        let mut transcript = Transcript::new(b"TEST");

        let circuit = composer.preprocess(
            &ck,
            &mut transcript,
            &EvaluationDomain::new(composer.circuit_size()).unwrap(),
        );

        let proof = composer.prove(&ck, &circuit, &mut transcript.clone());

        assert!(!proof.verify(&circuit, &mut transcript, &vk, &composer.public_inputs()));
    }
}
