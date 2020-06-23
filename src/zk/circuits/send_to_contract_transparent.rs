use crate::{db, zk::gadgets, NoteVariant, Transaction, TransactionItem};

use dusk_plonk::constraint_system::StandardComposer;
use dusk_plonk::proof_system::Proof;

/// This gadget constructs the circuit for a "Send To Contract Transparent" transaction.
pub fn send_to_contract_transparent_gadget(composer: &mut StandardComposer, tx: &Transaction) {
    // Define an accumulator, which will hold the amount being sent to the contract.
    let v: u64 = 0;

    // Inputs
    let db = db::Db::default();
    tx.inputs().iter().for_each(|input| {
        // Merkle openings + preimage knowledge + nullifier
        // TODO: get branch
        gadgets::merkle(composer, branch, input);
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

        // Tally up input value into `v`
        v += input.value();
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

        // Subtract output value from `v`
        v -= output.value();
    });

    // Inputs - outputs = 0
    gadgets::balance(composer, tx, v);
}