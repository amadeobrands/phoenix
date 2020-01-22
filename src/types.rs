use crate::{
    rpc, utils, CompressedEdwardsY, CompressedRistretto, EdwardsPoint, Error, RistrettoPoint,
    Scalar,
};

use std::convert::TryInto;

impl From<Scalar> for rpc::Scalar {
    fn from(s: Scalar) -> Self {
        rpc::Scalar {
            data: s.as_bytes().to_vec(),
        }
    }
}

impl Into<Scalar> for rpc::Scalar {
    fn into(self) -> Scalar {
        Scalar::from_bits(utils::safe_32_chunk(self.data.as_slice()))
    }
}

impl From<CompressedEdwardsY> for rpc::CompressedPoint {
    fn from(s: CompressedEdwardsY) -> Self {
        rpc::CompressedPoint {
            y: s.as_bytes().to_vec(),
        }
    }
}

impl Into<CompressedEdwardsY> for rpc::CompressedPoint {
    fn into(self) -> CompressedEdwardsY {
        CompressedEdwardsY::from_slice(&utils::safe_32_chunk(self.y.as_slice()))
    }
}

impl From<CompressedRistretto> for rpc::CompressedPoint {
    fn from(s: CompressedRistretto) -> Self {
        rpc::CompressedPoint {
            y: s.as_bytes().to_vec(),
        }
    }
}

impl Into<CompressedRistretto> for rpc::CompressedPoint {
    fn into(self) -> CompressedRistretto {
        CompressedRistretto::from_slice(&utils::safe_32_chunk(self.y.as_slice()))
    }
}

impl From<EdwardsPoint> for rpc::CompressedPoint {
    fn from(s: EdwardsPoint) -> Self {
        rpc::CompressedPoint {
            y: s.compress().as_bytes().to_vec(),
        }
    }
}

impl TryInto<EdwardsPoint> for rpc::CompressedPoint {
    type Error = Error;

    fn try_into(self) -> Result<EdwardsPoint, Self::Error> {
        let y: CompressedEdwardsY = self.into();
        y.decompress().ok_or(Error::InvalidPoint)
    }
}

impl From<RistrettoPoint> for rpc::CompressedPoint {
    fn from(s: RistrettoPoint) -> Self {
        rpc::CompressedPoint {
            y: s.compress().as_bytes().to_vec(),
        }
    }
}

impl TryInto<RistrettoPoint> for rpc::CompressedPoint {
    type Error = Error;

    fn try_into(self) -> Result<RistrettoPoint, Self::Error> {
        let y: CompressedRistretto = self.into();
        y.decompress().ok_or(Error::InvalidPoint)
    }
}
