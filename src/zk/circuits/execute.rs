use crate::{zk::gadgets, BlsScalar, Transaction, TransactionItem};

use dusk_plonk::constraint_system::StandardComposer;

/// This gadget constructs the circuit for an 'Execute' call on the DUSK token contract.
pub fn execute_gadget(composer: &mut StandardComposer, tx: &Transaction) {
    // Define an accumulator which we will use to prove that the sum of all inputs
    // equals the sum of all outputs.
    //
    // Note that we are not using the balance gadget here, since the fee output
    // needs to be a public input, and the balance gadget only constrains
    // the fee.
    let mut sum = composer.zero_var;

    tx.inputs().iter().for_each(|tx_input| {
        // Merkle opening, preimage knowledge
        // and nullifier.
        // TODO: get branch
        // gadgets::merkle(composer, branch, tx_input);
        gadgets::input_preimage(composer, tx_input);

        // TODO: ecc_gate function from PLONK
        //gadget::secret_key();

        gadgets::nullifier(composer, tx_input);
        gadgets::commitment(composer, tx_input);
        gadgets::range(composer, tx_input);

        // Constrain the sum of all of the inputs
        let value = composer.add_input(BlsScalar::from(tx_input.value()));
        sum = composer.add(
            (BlsScalar::one(), sum),
            (BlsScalar::one(), value),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
    });

    tx.outputs().iter().for_each(|tx_output| {
        gadgets::commitment(composer, tx_output);
        gadgets::range(composer, tx_output);

        // Constrain the sum of all outputs
        let value = composer.add_input(BlsScalar::from(tx_output.value()));
        sum = composer.add(
            (BlsScalar::one(), sum),
            (-BlsScalar::one(), value),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
    });

    let fee = *tx.fee();

    sum = composer.add(
        (-BlsScalar::one(), sum),
        (BlsScalar::one(), composer.zero_var),
        BlsScalar::zero(),
        BlsScalar::from(fee.value()),
    );

    composer.constrain_to_constant(sum, BlsScalar::zero(), BlsScalar::zero());
}
