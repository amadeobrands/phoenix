use crate::{zk::gadgets, Transaction};

use dusk_plonk::constraint_system::{StandardComposer};
use dusk_plonk::proof_system::Proof;

fn send_gadget(composer: &mut StandardComposer, tx: &Transaction) {}