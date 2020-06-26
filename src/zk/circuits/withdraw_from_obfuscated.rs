use crate::{
    db, zk::gadgets, BlsScalar, NoteVariant, Transaction, TransactionItem, TransactionOutput,
};

use dusk_plonk::constraint_system::StandardComposer;
use kelvin::Blake2b;

/// This gadget constructs the circuit for a "Withdraw from contract obfuscated" transaction.
pub fn withdraw_from_contract_obfuscated_gadget(
    composer: &mut StandardComposer,
    tx: &Transaction,
    m: &TransactionOutput,
) {
    // Prove the knowledge of commitment to m
    gadgets::commitment(composer, m);
    // Prove message m is in range
    gadgets::range(composer, m);

    // Prove the knowledge of commitment to remainder

    // Prove remainder is in range

    // Outputs
    tx.outputs().iter().for_each(|tx_output| {
        // Commitment preimage knowledge + range proof
        match tx_output.note() {
            NoteVariant::Obfuscated(_) => {
                gadgets::commitment(composer, tx_output);
                gadgets::range(composer, tx_output);
            }
            _ => {}
        }
    });

    // Message - remiander - output = 0
    let mut sum = gadgets::balance(composer, tx);
    let value = composer.add_input(BlsScalar::from(m.value));
    sum = composer.add(
        (BlsScalar::one(), sum),
        (-BlsScalar::one(), value),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );

    composer.constrain_to_constant(sum, BlsScalar::zero(), BlsScalar::zero());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto, Note, NoteGenerator, ObfuscatedNote, SecretKey, Transaction, TransparentNote,
    };
    use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
    use dusk_plonk::fft::EvaluationDomain;
    use merlin::Transcript;


    #[test]
    fn test_withdraw_obfuscated() {
        let mut tx = Transaction::default();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 100;
        let note = ObfuscatedNote::output(&pk, value).0;
        let merkle_opening = crypto::MerkleProof::mock(note.hash());
        tx.push_input(note.to_transaction_input(merkle_opening, sk).unwrap())
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 95;
        let (note, blinding_factor) = ObfuscatedNote::output(&pk, value);
        tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 2;
        let (note, blinding_factor) = ObfuscatedNote::output(&pk, value);
        tx.push_output(note.to_transaction_output(value, blinding_factor, pk))
            .unwrap();

        let sk = SecretKey::default();
        let pk = sk.public_key();
        let value = 3;
        let (note, blinding_factor) = TransparentNote::output(&pk, value);
        tx.set_fee(note.to_transaction_output(value, blinding_factor, pk));

        let mut composer = StandardComposer::new();

        withdraw_from_contract_obfuscated_gadget(&mut composer, &tx, &m);

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
}