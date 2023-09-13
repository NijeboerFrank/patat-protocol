use snow::{Keypair, Builder};
use snow::params::NoiseParams;

pub fn get_keys() -> Result<(Builder<'static>, Keypair, Keypair), &'static str> {
    let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let builder = Builder::new(params.clone());

    let client_keypair = builder
        .generate_keypair()
        .expect("Could not generate client keypair");
    let server_keypair = builder
        .generate_keypair()
        .expect("Could not generate server keypair");
    Ok((builder, client_keypair, server_keypair))
}
