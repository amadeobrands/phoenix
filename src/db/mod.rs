use crate::{Error, Idx, Note, NoteUtxoType, Nullifier, Transaction, TransactionItem};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[cfg(test)]
mod tests;

pub struct Db {
    // TODO - HashMap and HashSet implementation to emulate KVS. Use Kelvin?
    notes: Arc<Mutex<HashMap<Idx, Box<dyn Note>>>>,
    nullifiers: Arc<Mutex<HashSet<Nullifier>>>,
}

impl Db {
    pub fn new() -> Result<Self, Error> {
        Ok(Db {
            notes: Arc::new(Mutex::new(HashMap::new())),
            nullifiers: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    // TODO - Should be able to rollback state in case of failure
    pub fn store(&self, transaction: &Transaction) -> Result<Vec<Idx>, Error> {
        let fee = transaction.fee();

        let fee_idx = self.store_transaction_item(fee)?.ok_or(Error::FeeOutput)?;
        let notes = vec![fee_idx];

        transaction.items().iter().try_fold(notes, |mut v, i| {
            let idx = self.store_transaction_item(i)?;
            if let Some(idx_inserted) = idx {
                v.push(idx_inserted);
            }

            Ok(v)
        })
    }

    /// Attempt to store a given transaction item.
    ///
    /// If its an unspent output, will return the idx of the stored note.
    pub fn store_transaction_item(&self, item: &TransactionItem) -> Result<Option<Idx>, Error> {
        if item.utxo() == NoteUtxoType::Input {
            let nullifier = *item.nullifier();
            item.note().validate_nullifier(&nullifier)?;

            let mut nullifiers = self.nullifiers.try_lock()?;
            nullifiers.insert(nullifier);

            Ok(None)
        } else {
            self.store_unspent_note(item.note()).map(|idx| Some(idx))
        }
    }

    pub fn store_unspent_note(&self, mut note: Box<dyn Note>) -> Result<Idx, Error> {
        let mut notes = self.notes.try_lock()?;

        let idx = Idx(notes.len() as u64);
        note.set_idx(idx);
        notes.insert(idx, note);

        Ok(idx)
    }

    pub fn fetch_note<N: Note>(&self, idx: &Idx) -> Result<N, Error> {
        let notes = self.notes.try_lock()?;
        let note = notes
            .get(idx)
            .map(|n| n.box_clone())
            .ok_or(Error::Generic)?;

        // TODO - As a temporary solution until Kelvin is implemented, using very unsafe code
        Ok(Db::note_box_into(note))
    }

    pub fn fetch_nullifier(&self, nullifier: &Nullifier) -> Result<Option<()>, Error> {
        let nullifiers = self.nullifiers.try_lock()?;
        Ok(if nullifiers.contains(nullifier) {
            Some(())
        } else {
            None
        })
    }

    pub fn note_box_into<N>(note: Box<dyn Note>) -> N {
        // TODO - As a temporary solution until Kelvin is implemented, using very unsafe code
        unsafe { Box::into_raw(note).cast::<N>().read() }
    }
}