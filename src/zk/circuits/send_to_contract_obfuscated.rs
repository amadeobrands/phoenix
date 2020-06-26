use crate::{db, BlsScalar, zk::gadgets, NoteVariant, Transaction, TransactionItem, TransactionOutput};
use kelvin::Blake2b;
use dusk_plonk::constraint_system::StandardComposer;
use dusk_plonk::proof_system::Proof;

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
