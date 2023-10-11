use anyhow::Result;
use rs_merkle::{MerkleProof, MerkleTree, algorithms::Sha256};

use crate::evidence::Evidence;

pub struct EvidenceTree<'a> {
    evidence: Vec<&'a dyn Evidence>,
    tree: Option<MerkleTree<Sha256>>,
}

impl<'a> EvidenceTree<'a> {
    pub fn new(evidence: Vec<&'a dyn Evidence>) -> EvidenceTree {
        EvidenceTree {
            evidence,
            tree: None,
        }
    }

    fn ensure_tree(&mut self) {
        if self.tree.is_none() {
            let leaves: Vec<[u8; 32]> = self
                .evidence
                .iter()
                .map(|x| x.build_root().unwrap())
                .collect();
            self.tree = Some(MerkleTree::<Sha256>::from_leaves(&leaves));
        }
    }

    pub fn get_root(&mut self) -> Result<[u8; 32]> {
	self.ensure_tree();
	let root = self.tree.clone().unwrap().root().unwrap();
        Ok(root)
    }

    pub fn get_proof(&mut self, indices: &[usize]) -> Result<Vec<u8>> {
	self.ensure_tree();
	Ok(self.tree.clone().unwrap().proof(indices).to_bytes())
    }

    pub fn prove_subtree(&mut self, proof: Vec<u8>) -> Result<bool> {
        let proof = MerkleProof::<Sha256>::from_bytes(&proof)?;

        let other_leaves: &Vec<[u8; 32]> = &self.evidence[1..1]
            .iter()
            .map(|x| x.build_root().unwrap())
            .collect();

        proof.verify(
            self.get_root().unwrap(),
            &vec![0],
            other_leaves,
            self.evidence.len(),
        );

        Ok(true)
    }
}
