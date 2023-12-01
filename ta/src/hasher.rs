use optee_utee::{AlgorithmId, Digest};
use proto::HASHLEN;

use std::convert::TryInto;
use std::default::Default;
use std::hash::Hasher;

use merkle_light::hash::Algorithm;

pub struct PatatHashAlgorithm {
    op: Digest,
}

impl PatatHashAlgorithm {
    pub fn new() -> PatatHashAlgorithm {
        PatatHashAlgorithm {
            op: Digest::allocate(AlgorithmId::Sha256).unwrap(),
        }
    }
}

impl Hasher for PatatHashAlgorithm {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.op.update(msg);
    }

    #[inline]
    fn finish(&self) -> u64 {
        let mut hash = [0u8; HASHLEN];
        let length = self.op.do_final(&[], &mut hash).unwrap();
        length.try_into().unwrap()
    }
}

impl Default for PatatHashAlgorithm {
    fn default() -> PatatHashAlgorithm {
        PatatHashAlgorithm::new()
    }
}

impl Algorithm<[u8; HASHLEN]> for PatatHashAlgorithm {
    #[inline]
    fn hash(&mut self) -> [u8; HASHLEN] {
        let mut h = [0u8; HASHLEN];
        self.op.do_final(&[], &mut h);
        h
    }

    #[inline]
    fn reset(&mut self) {
        self.op = Digest::allocate(AlgorithmId::Sha256).unwrap();
    }
}
