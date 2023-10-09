use anyhow::Result;
use rs_merkle::{algorithms::Sha256, MerkleTree, MerkleProof};

use crate::evidence::Evidence;

pub struct EvidenceTree<'a> {
    evidence: Vec<&'a dyn Evidence>,
}

impl<'a> EvidenceTree<'a> {
    pub fn new(evidence: Vec<&'a dyn Evidence>) -> EvidenceTree {
        EvidenceTree { evidence }
    }

    pub fn get_root(&self) -> Result<[u8; 32]> {
        let leaves: Vec<[u8; 32]> = self
            .evidence
            .iter()
            .map(|x| x.build_root().unwrap())
            .collect();

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let merkle_root = merkle_tree.root().unwrap();

        Ok(merkle_root)
    }

    pub fn prove_subtree(&self, subtree_root: [u8; 32]) -> Result<bool> {
	let proof = MerkleProof::<Sha256>::from_bytes(&subtree_root)?;

	proof.verify(self.get_root()?, &vec![0], );
	
	Ok(true)
    }
}
