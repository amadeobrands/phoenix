use crate::{db, zk::gadgets, Transaction};

use dusk_plonk::constraint_system::{Proof, StandardComposer};

/// This gadget constructs the circuit for a "Send To Contract Transparent" transaction.
pub fn send_to_contract_transparent_gadget(
    composer: &mut StandardComposer,
    tx: &Transaction,
    v: u64,
) {
    // Merkle openings + preimage knowledge + nullifier
    let db = db::Db::default();
    tx.inputs().iter().for_each(|input| {
        // TODO: get branch
        gadgets::merkle(composer, branch, input);
        gadgets::input_preimage(composer, input);
        gadgets::nullifier(composer, input);
    });

    // Commitment knowledge + range proof
    tx.inputs().iter().for_each(|input| {
        match input.note() {
            NoteVariant::Obfuscated => {
                gadgets::commitment(composer, input);
                gadgets::range(composer, input);
            },
            _ => {},
        }
    }

    tx.outputs().iter().for_each(|output| {
        match output.note() {
            NoteVariant::Obfuscated => {
                gadgets::commitment(composer, output);
                gadgets::range(composer, output);
            },
            _ => {},
        }
    }

    // Inputs - outputs = 0
    gadgets::balance(composer, tx, v);
}
