use merkle_light::hash::{Algorithm, Hashable};
use optee_utee::{AlgorithmId, Digest};
use std::default::Default;
use std::hash::Hasher;
use optee_utee::trace_println;
use proto::HASHLEN;

pub struct HashAlgorithm {
    op: Digest,
}

impl HashAlgorithm {
    pub fn new() -> HashAlgorithm {
        HashAlgorithm {
            op: Digest::allocate(AlgorithmId::Sha256).unwrap(),
        }
    }
}

impl Hasher for HashAlgorithm {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        trace_println!("[++] Write called");
        self.op.update(msg);
    }

    #[inline]
    fn finish(&self) -> u64 {
        trace_println!("[++] Finish called");
        let mut hash = [0u8; HASHLEN];
        let length = self.op.do_final(&[], &mut hash).unwrap();
        let h = &hash[..length];
        trace_println!("{:?}", h);
        0
    }
}

impl Default for HashAlgorithm {
    fn default() -> HashAlgorithm {
        HashAlgorithm::new()
    }
}

impl Algorithm<[u8; HASHLEN]> for HashAlgorithm {
    #[inline]
    fn hash(&mut self) -> [u8; HASHLEN] {
        trace_println!("[++] Hash called");
        let mut h = [0u8; HASHLEN];
        self.op.do_final(&[], &mut h);
        h
    }

    #[inline]
    fn reset(&mut self) {
        trace_println!("[++] Reset called");
        self.op = Digest::allocate(AlgorithmId::Sha256).unwrap();
    }
}
