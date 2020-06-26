use crate::{db, zk::gadgets, BlsScalar, NoteVariant, Transaction, TransactionItem};

use dusk_plonk::constraint_system::StandardComposer;
use kelvin::Blake2b;

/// This gadget constructs the circuit for a 'Send' call on a token contract.
pub fn send_gadget(composer: &mut StandardComposer, tx: &Transaction) {
    let db = db::Db::<Blake2b>::default();
    tx.inputs().iter().for_each(|tx_input| {
        // Merkle opening, preimahge knowledge
        // and nullifier.
        // TODO: get branch
        // gadgets::merkle(composer, branch, tx_input);
        gadgets::input_preimage(composer, tx_input);
        gadgets::nullifier(composer, tx_input);
        //gadget::secret_key();

        // Commitment knowledge and range proof
        // for inputs. If the contained note is
        // obfuscated,it will also include statements
        // about the commitment preimage, and a range proof.
        match tx_input.note() {
            NoteVariant::Obfuscated(_) => {
                gadgets::commitment(composer, tx_input);
                gadgets::range(composer, tx_input);
            }
            _ => {}
        }
    });

    // Commitment knowledge and range proof
    // for outputs. If the contained note is
    // obfuscated,it will also include statements
    // about the commitment preimage, and a range proof.
    tx.outputs()
        .iter()
        .for_each(|tx_output| match tx_output.note() {
            NoteVariant::Obfuscated(_) => {
                gadgets::commitment(composer, tx_output);
                gadgets::range(composer, tx_output);
            }
            _ => {}
        });

    // Inputs - outputs = 0
    let sum = gadgets::balance(composer, tx);
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
    fn test_send_transparent() {
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

        send_gadget(&mut composer, &tx);

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
    fn test_send_obfuscated() {
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

        send_gadget(&mut composer, &tx);

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
