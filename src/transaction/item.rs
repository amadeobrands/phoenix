use crate::{Note, NoteUtxoType, Nullifier, Scalar, TransparentNote};

#[derive(Debug)]
pub struct TransactionItem {
    note: Box<dyn Note>,
    nullifier: Nullifier,
    value: u64,
    blinding_factor: Scalar,
}

impl Clone for TransactionItem {
    fn clone(&self) -> Self {
        TransactionItem {
            note: self.note.box_clone(),
            nullifier: self.nullifier.clone(),
            value: self.value,
            blinding_factor: self.blinding_factor.clone(),
        }
    }
}

impl Default for TransactionItem {
    fn default() -> Self {
        let note = TransparentNote::default();
        let nullifier = Nullifier::default();
        let value = 0;
        let blinding_factor = Scalar::one();

        TransactionItem::new(note, nullifier, value, blinding_factor)
    }
}

impl TransactionItem {
    pub fn new<N: Note>(
        note: N,
        nullifier: Nullifier,
        value: u64,
        blinding_factor: Scalar,
    ) -> Self {
        TransactionItem {
            note: note.box_clone(),
            nullifier,
            value,
            blinding_factor,
        }
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn blinding_factor(&self) -> &Scalar {
        &self.blinding_factor
    }

    pub fn utxo(&self) -> NoteUtxoType {
        self.note.utxo()
    }

    pub fn note(&self) -> Box<dyn Note> {
        self.note.box_clone()
    }

    pub fn nullifier(&self) -> &Nullifier {
        &self.nullifier
    }
}