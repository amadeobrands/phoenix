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
