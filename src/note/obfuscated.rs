use super::{NoteType, NoteUtxoType, PhoenixIdx, PhoenixNote};
use crate::{crypto, hash, utils, CompressedRistretto, PhoenixValue, PublicKey, Scalar};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscatedNote {
    utxo: NoteUtxoType,
    commitments: Vec<CompressedRistretto>,
    r_p: CompressedRistretto,
    pk_r: CompressedRistretto,
    idx: PhoenixIdx,
    encrypted_value: Vec<u8>,
    encrypted_blinding_factors: Vec<u8>,
}

impl ObfuscatedNote {
    pub fn new(
        utxo: NoteUtxoType,
        commitments: Vec<CompressedRistretto>,
        r_p: CompressedRistretto,
        pk_r: CompressedRistretto,
        idx: PhoenixIdx,
        encrypted_value: Vec<u8>,
        encrypted_blinding_factors: Vec<u8>,
    ) -> Self {
        ObfuscatedNote {
            utxo,
            commitments,
            r_p,
            pk_r,
            idx,
            encrypted_value,
            encrypted_blinding_factors,
        }
    }
}

impl PhoenixNote for ObfuscatedNote {
    fn utxo(&self) -> NoteUtxoType {
        self.utxo
    }

    fn note(&self) -> NoteType {
        NoteType::Obfuscated
    }

    fn output(pk: &PublicKey, value: u64) -> Self {
        // TODO - Grant r is in Fp
        let r = utils::gen_random_scalar();
        let r_p = utils::scalar_to_field(&r);
        let a_p = pk.a_p;
        let b_p = pk.b_p;
        let pk_r = hash::hash_in_p(&r * &a_p) + b_p;

        let idx = PhoenixIdx::default();
        let encrypted_value = crypto::encrypt(pk_r, value.to_le_bytes().to_vec());
        let phoenix_value = PhoenixValue::new(idx, Scalar::from(value));
        let commitments = phoenix_value.commitments().clone();
        let blinding_factors = phoenix_value.blinding_factors();
        let blinding_factors = blinding_factors.iter().fold(vec![], |mut v, f| {
            v.extend_from_slice(&f.as_bytes()[..]);
            v
        });
        let encrypted_blinding_factors = crypto::encrypt(pk_r, blinding_factors);

        ObfuscatedNote::new(
            NoteUtxoType::Output,
            commitments,
            r_p.compress(),
            pk_r.compress(),
            idx,
            encrypted_value,
            encrypted_blinding_factors,
        )
    }
}
