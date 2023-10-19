use anyhow::Result;
use rs_merkle::{algorithms::Sha256, MerkleTree};

use crate::evidence::Evidence;

/// Root Evidence, consisting of multiple [Evidence] structs, for sending
/// through a [PatatConnection](crate::patat_connection::PatatConnection).
pub struct CombinedEvidence {
    tree: MerkleTree<Sha256>,
    pub tree_root: Option<[u8; 32]>,
}

impl CombinedEvidence {
    pub fn new() -> CombinedEvidence {
	let tree = MerkleTree::new();
	let tree_root = tree.root();
        CombinedEvidence {
            tree,
            tree_root,
        }
    }

    pub fn append_evidence(&mut self, evidence: Vec<Box<dyn Evidence>>) {
        let mut leaves: Vec<[u8; 32]> = evidence.iter().map(|e| e.build_root().unwrap()).collect();
        self.tree.append(&mut leaves);
	self.tree.commit();
	self.tree_root = self.tree.root();
    }

    pub fn insert_evidence(&mut self, evidence: Box<dyn Evidence>) {
	self.tree.insert(evidence.build_root().unwrap());
	self.tree.commit();
	self.tree_root = self.tree.root();
    }

    pub fn insert_evidence_root(&mut self, evidence_root: [u8; 32]) {
	self.tree.insert(evidence_root);
	self.tree.commit();
	self.tree_root = self.tree.root();
    }

    pub fn get_proof(&mut self, indices: &[usize]) -> Result<Vec<u8>> {
        Ok(self.tree.proof(indices).to_bytes())
    }

    pub fn prove_subtree(&mut self, _proof: Vec<u8>) -> Result<bool> {
        Ok(true)
    }
}
