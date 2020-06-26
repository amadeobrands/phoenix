use crate::{db, zk::gadgets, BlsScalar, NoteVariant, Transaction, TransactionItem};

use dusk_plonk::constraint_system::StandardComposer;
use kelvin::Blake2b;

pub fn withdraw_from_obfuscated(composer: &mut StandardComposer, tx: &Transaction) {}
