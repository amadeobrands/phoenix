use crate::{zk::gadgets, Transaction};

use dusk_plonk::constraint_system::{Proof, StandardComposer};

fn send_gadget(composer: &mut StandardComposer, tx: &Transaction) {
    
    let db = db::Db::default();
    tx.inputs().iter().for_each(|tx_input| {
        // Merkle opening, preimahge knowledge
        // and nullifier.
        // TODO: get branch
        gadgets::merkle(composer, branch, tx_input);
        gadget::premia(composer, tx_input);
        gadget::preimage(composer, tx_input);
        //gadget::secret_key();
    

        // Commitment knowledge and range proof
        // for inputs. If the contained note is 
        // obfuscated,it will also include statements 
        // about the commitment preimage, and a range proof.
        match input.note() {
            NoteVariant::Obfuscated => {
                gadgets::commitment(composer, tx_input);
                gadgets::range(composer, tx_input);
            },
            _ => {},
        }
    });

    // Commitment knowledge and range proof
    // for outputs. If the contained note is 
    // obfuscated,it will also include statements 
    // about the commitment preimage, and a range proof.
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
    let sum = gadgets::balance(composer, tx);
    composer.constrain_to_zero(sum, BlsScalar::zero(), BlsScalar::zero());


}
