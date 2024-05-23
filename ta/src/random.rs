// OP-TEE TA imports
use optee_utee::crypto_op::Random;

use rand_core::CryptoRng;
use rand_core::{RngCore, Error};

pub struct PatatRng;

impl RngCore for PatatRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Random::generate(dest);
    }

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Error> {
        unimplemented!()
    }
}

impl CryptoRng for PatatRng {}
