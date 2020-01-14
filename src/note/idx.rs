use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Idx(pub u64);

impl Idx {
    pub fn to_vec(self) -> Vec<u8> {
        self.into()
    }
}

impl From<u64> for Idx {
    fn from(idx: u64) -> Self {
        Idx(idx)
    }
}

impl Into<Vec<u8>> for Idx {
    fn into(self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

impl Hash for Idx {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}