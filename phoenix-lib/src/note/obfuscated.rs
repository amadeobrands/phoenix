use super::{Idx, Note, NoteGenerator, NoteUtxoType};
use crate::{
    crypto, rpc, utils, CompressedRistretto, Db, EdwardsPoint, Error, Nonce, NoteType, PublicKey,
    R1CSProof, Scalar, Value, ViewKey,
};

use std::cmp;
use std::convert::{TryFrom, TryInto};

use sha2::{Digest, Sha512};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObfuscatedNote {
    utxo: NoteUtxoType,
    commitment: CompressedRistretto,
    nonce: Nonce,
    r_g: EdwardsPoint,
    pk_r: EdwardsPoint,
    idx: Idx,
    pub(crate) encrypted_value: Vec<u8>,
    pub(crate) encrypted_blinding_factor: Vec<u8>,
}

impl ObfuscatedNote {
    pub fn new(
        utxo: NoteUtxoType,
        commitment: CompressedRistretto,
        nonce: Nonce,
        r_g: EdwardsPoint,
        pk_r: EdwardsPoint,
        idx: Idx,
        encrypted_value: Vec<u8>,
        encrypted_blinding_factor: Vec<u8>,
    ) -> Self {
        ObfuscatedNote {
            utxo,
            commitment,
            nonce,
            r_g,
            pk_r,
            idx,
            encrypted_value,
            encrypted_blinding_factor,
        }
    }
}

impl NoteGenerator for ObfuscatedNote {
    fn input(db: &Db, idx: &Idx) -> Result<Self, Error> {
        db.fetch_note(idx)
    }

    fn output(pk: &PublicKey, value: u64) -> (Self, Scalar) {
        let idx = Idx::default();
        let nonce = utils::gen_nonce();

        let (r, r_g, pk_r) = Self::generate_pk_r(pk);

        let phoenix_value = Value::new(Scalar::from(value));

        let blinding_factor = *phoenix_value.blinding_factor();
        let commitment = *phoenix_value.commitment();

        let encrypted_value = ObfuscatedNote::encrypt_value(&r, pk, &nonce, value);
        let encrypted_blinding_factor =
            ObfuscatedNote::encrypt_blinding_factor(&r, pk, &nonce, &blinding_factor);

        let note = ObfuscatedNote::new(
            NoteUtxoType::Output,
            commitment,
            nonce,
            r_g,
            pk_r,
            idx,
            encrypted_value,
            encrypted_blinding_factor,
        );

        (note, blinding_factor)
    }
}

impl Note for ObfuscatedNote {
    fn hash(&self) -> Scalar {
        // TODO - Use poseidon sponge, when available
        let mut hasher = Sha512::default();

        hasher.input(&[self.utxo.into()]);
        hasher.input(self.commitment.as_bytes());
        hasher.input(&self.nonce);
        hasher.input(self.r_g.compress().as_bytes());
        hasher.input(self.pk_r.compress().as_bytes());
        hasher.input(self.idx.clone().to_vec());
        hasher.input(&self.encrypted_value);
        hasher.input(&self.encrypted_blinding_factor);

        Scalar::from_hash(hasher)
    }

    fn box_clone(&self) -> Box<dyn Note> {
        Box::new(self.clone())
    }

    fn utxo(&self) -> NoteUtxoType {
        self.utxo
    }

    fn set_utxo(&mut self, utxo: NoteUtxoType) {
        self.utxo = utxo;
    }

    fn note(&self) -> NoteType {
        NoteType::Obfuscated
    }

    fn idx(&self) -> &Idx {
        &self.idx
    }

    fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    fn r_g(&self) -> &EdwardsPoint {
        &self.r_g
    }

    fn pk_r(&self) -> &EdwardsPoint {
        &self.pk_r
    }

    fn set_idx(&mut self, idx: Idx) {
        self.idx = idx;
    }

    fn value(&self, vk: Option<&ViewKey>) -> u64 {
        let vk = vk.copied().unwrap_or_default();

        let decrypt_value =
            crypto::decrypt(&self.r_g, &vk, &self.nonce, self.encrypted_value.as_slice());

        let mut v = [0x00u8; 8];
        let chunk = cmp::min(decrypt_value.len(), 8);
        (&mut v[0..chunk]).copy_from_slice(&decrypt_value.as_slice()[0..chunk]);

        u64::from_le_bytes(v)
    }

    fn encrypted_value(&self) -> Option<&Vec<u8>> {
        Some(&self.encrypted_value)
    }

    fn commitment(&self) -> &CompressedRistretto {
        &self.commitment
    }

    fn blinding_factor(&self, vk: &ViewKey) -> Scalar {
        let blinding_factor = crypto::decrypt(
            &self.r_g,
            vk,
            &self.nonce.increment_le(),
            self.encrypted_blinding_factor.as_slice(),
        );

        Scalar::from_bits(utils::safe_32_chunk(blinding_factor.as_slice()))
    }

    fn encrypted_blinding_factor(&self) -> &Vec<u8> {
        &self.encrypted_blinding_factor
    }

    fn prove_value(&self, vk: &ViewKey) -> Result<R1CSProof, Error> {
        let value = self.value(Some(vk));
        let blinding_factor = self.blinding_factor(vk);

        let phoenix_value = Value::with_blinding_factor(value, blinding_factor);

        phoenix_value.prove(value).map_err(Error::generic)
    }

    fn verify_value(&self, proof: &R1CSProof) -> Result<(), Error> {
        Value::with_commitment(*self.commitment())
            .verify(proof)
            .map_err(Error::generic)
    }
}

impl From<ObfuscatedNote> for rpc::Note {
    fn from(note: ObfuscatedNote) -> rpc::Note {
        let note_type = rpc::NoteType::Obfuscated.into();
        let pos = note.idx.into();
        let io = rpc::InputOutput::from(note.utxo).into();
        let nonce = Some(note.nonce.into());
        let r_g = Some(note.r_g.into());
        let pk_r = Some(note.pk_r.into());
        let commitment = Some(note.commitment.into());
        let encrypted_blinding_factor = note.encrypted_blinding_factor;
        let value = Some(rpc::note::Value::EncryptedValue(note.encrypted_value));

        rpc::Note {
            note_type,
            pos,
            io,
            nonce,
            r_g,
            pk_r,
            commitment,
            encrypted_blinding_factor,
            value,
        }
    }
}

impl TryFrom<rpc::Note> for ObfuscatedNote {
    type Error = Error;

    fn try_from(note: rpc::Note) -> Result<Self, Self::Error> {
        if rpc::NoteType::try_from(note.note_type)? != NoteType::Obfuscated {
            return Err(Error::InvalidParameters);
        }

        let utxo = rpc::InputOutput::try_from(note.io)?.into();
        let nonce = note.nonce.ok_or(Error::InvalidParameters)?.try_into()?;
        let r_g = note.r_g.ok_or(Error::InvalidParameters)?.try_into()?;
        let pk_r = note.pk_r.ok_or(Error::InvalidParameters)?.try_into()?;
        let idx = note.pos.ok_or(Error::InvalidParameters)?;
        let commitment = note.commitment.ok_or(Error::InvalidParameters)?.into();
        let encrypted_blinding_factor = note.encrypted_blinding_factor;

        let encrypted_value = match note.value.ok_or(Error::InvalidParameters)? {
            rpc::note::Value::TransparentValue(_) => Err(Error::InvalidParameters),
            rpc::note::Value::EncryptedValue(v) => Ok(v),
        }?;

        Ok(ObfuscatedNote::new(
            utxo,
            commitment,
            nonce,
            r_g,
            pk_r,
            idx,
            encrypted_value,
            encrypted_blinding_factor,
        ))
    }
}

impl TryFrom<rpc::DecryptedNote> for ObfuscatedNote {
    type Error = Error;

    fn try_from(note: rpc::DecryptedNote) -> Result<Self, Self::Error> {
        let utxo = NoteUtxoType::Output;
        let commitment = note.commitment.ok_or(Error::InvalidParameters)?.into();
        let nonce = note.nonce.ok_or(Error::InvalidParameters)?.try_into()?;
        let r_g = note.r_g.ok_or(Error::InvalidParameters)?.try_into()?;
        let pk_r = note.pk_r.ok_or(Error::InvalidParameters)?.try_into()?;
        let idx = note.pos.ok_or(Error::InvalidParameters)?;
        let encrypted_blinding_factor = note.encrypted_blinding_factor;
        let encrypted_value = match note.raw_value.ok_or(Error::InvalidParameters)? {
            rpc::decrypted_note::RawValue::EncryptedValue(v) => Ok(v),
            _ => Err(Error::InvalidParameters),
        }?;

        Ok(ObfuscatedNote::new(
            utxo,
            commitment,
            nonce,
            r_g,
            pk_r,
            idx,
            encrypted_value,
            encrypted_blinding_factor,
        ))
    }
}