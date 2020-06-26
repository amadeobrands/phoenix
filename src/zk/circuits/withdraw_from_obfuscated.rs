use crate::{db, BlsScalar, zk::gadgets, NoteVariant, Transaction, TransactionItem, TransactionOutput};
use kelvin::Blake2b;
use dusk_plonk::constraint_system::StandardComposer;


/// This gadget constructs the circuit for a "Withdraw from Obfuscated" transaction.
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
