use crate::{zk::gadgets, Transaction};

use dusk_plonk::constraint_system::{Proof, StandardComposer};

fn send_gadget(composer: &mut StandardComposer, tx: &Transaction) {
    tx.inputs().iter().for_each(|tx_input|{
        gadgets::merkle(composer, branch, tx_input);
        gadget::nullifier(composer, tx_input);
        gadget::preimage(composer, tx_input);
        //gadget::secret_key();
    });

    // Commitment knowledge and range proof
    // for inputs
    tx.inputs().iter().for_each(|tx_input| {
        match input.note() {
            NoteVariant::Obfuscated => {
                gadgets::commitment(composer, tx_input);
                gadgets::range(composer, tx_input);
            },
            _ => {},
        }
    }

    // Commitment knowledge and range proof
    // for inputs
    tx.outputs().iter().for_each(|tx_output| {
        match output.note() {
            NoteVariant::Obfuscated => {
                gadgets::commitment(composer, tx_output);
                gadgets::range(composer, tx_output);
            },
            _ => {},
        }
    }

    // Inputs - outputs = 0
    gadgets::balance(composer, tx, 0);


}
