use anyhow::Result;
use rs_merkle::{MerkleProof, algorithms::Sha256};

/// The Verifier can verify whether  
pub struct Verifier;

impl Verifier {
    pub fn new() -> Self {
	Verifier
    }

    pub fn prove_tree(&self, root: [u8; 32], subtree: [u8; 32], proof: Vec<u8>, size: usize) -> Result<bool> {
	let proof = MerkleProof::<Sha256>::try_from(proof)?;
	Ok(proof.verify(root, &[0], &[subtree], size))
    }
}

