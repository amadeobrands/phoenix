use crate::{
    db, zk::gadgets, BlsScalar, NoteVariant, Transaction, TransactionItem, TransactionOutput,
};
use dusk_plonk::constraint_system::StandardComposer;
use dusk_plonk::proof_system::Proof;
use kelvin::Blake2b;

/// This gadget constructs the circuit for a "Send To Contract Obfuscated" transaction.
pub fn send_to_contract_obfuscated_gadget(
    composer: &mut StandardComposer,
    tx: &Transaction,
    m: &TransactionOutput,
) {
    // Inputs
    let db = db::Db::<Blake2b>::default();
    tx.inputs().iter().for_each(|input| {
        // Merkle openings + preimage knowledge + nullifier
        // TODO: get branch
        // gadgets::merkle(composer, branch, input);
        gadgets::input_preimage(composer, input);
        gadgets::nullifier(composer, input);

        // Secret key knowledge
        // TODO: insert `ecc_gate` function from PLONK

        // If the contained note is obfuscated, also include statements about
        // the commitment preimage, and a range proof.
        match input.note() {
            NoteVariant::Obfuscated(_) => {
                gadgets::commitment(composer, input);
                gadgets::range(composer, input);
            }
            _ => {}
        }
    });

    // Outputs
    tx.outputs().iter().for_each(|output| {
        // Commitment preimage knowledge + range proof
        match output.note() {
            NoteVariant::Obfuscated(_) => {
                gadgets::commitment(composer, output);
                gadgets::range(composer, output);
            }
            _ => {}
        }
    });

    // Prove commitment knowledge of M
    gadgets::commitment(composer, m);
    // Prove commitment of M is in range
    gadgets::range(composer, m);

    // Inputs - outputs = 0
    let mut sum = gadgets::balance(composer, tx);
    let value = composer.add_input(BlsScalar::from(m.value));
    sum = composer.add(
        (BlsScalar::one(), sum),
        (-BlsScalar::one(), value),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );

    composer.constrain_to_constant(sum, BlsScalar::zero(), BlsScalar::zero());

    // TODO: Prove knowledge of encrypted m.value and m.blinding_factor
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
    fn test_send_to_contract_obfuscated() {
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
        let output = note.to_transaction_output(value, blinding_factor, pk);

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

        send_to_contract_obfuscated_gadget(&mut composer, &tx, &output);

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
