use crate::{zk::gadgets, Transaction};

use dusk_plonk::constraint_system::{StandardComposer};
use dusk_plonk::proof_system::Proof;

fn send_gadget(composer: &mut StandardComposer, tx: &Transaction) {
    tx.inputs().iter().for_each(|tx_input| {
        // Merkle opening, preimahge knowledge
        // and nullifier.
        // TODO: get branch
        // gadgets::merkle(composer, branch, tx_input);
        gadgets::input_preimage(composer, tx_input);
        //gadget::secret_key();
        gadgets::nullifier(composer, tx_input);
        gadgets::commitment(composer, tx_input);
        gadgets::range(composer, tx_input);
        let value = composer.add_input(BlsScalar::from(item.value()));
        sum = composer.add(
            (BlsScalar::one(), sum),
            (BlsScalar::one(), value),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
    }
    
    tx.outputs().iter().for_each(|tx_output| {
        gadgets::commitment(composer, tx_output);
        gadgets::range(composer, tx_output);
        let value = composer.add_input(BlsScalar::from(item.value()));
        sum = composer.add(
            (BlsScalar::one(), sum),
            (-BlsScalar::one(), value),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
    }

    let fee = *tx.fee();

    let value = composer.add_input(BlsScalar::from(fee.value()));
    sum = composer.add(
        (BlsScalar::one(), sum),
        (-BlsScalar::one(), value),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );

    sum

    composer.constrain_to_constant(sum, BlsScalar::zero(), BlsScalar::zero());
}
