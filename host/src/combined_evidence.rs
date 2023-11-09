use anyhow::Result;
use rs_merkle::{algorithms::Sha256, MerkleTree, MerkleProof};

/// Root Evidence, consisting of multiple [Evidence] structs, for sending
/// through a [PatatConnection](crate::patat_connection::PatatConnection).
pub struct CombinedEvidence {
    tree: MerkleTree<Sha256>,
}

impl CombinedEvidence {
    pub fn new(verifier_tree_root: [u8; 32], relying_party_tree_root: [u8; 32]) -> CombinedEvidence {
        let tree = MerkleTree::<Sha256>::from_leaves(&[verifier_tree_root, relying_party_tree_root]);
        CombinedEvidence {
            tree,
        }
    }

    pub fn get_root(&self) -> [u8; 32] {
        self.tree.root().unwrap().into()
    }

    fn get_proof(&mut self, indices: &[usize]) -> Result<Vec<u8>> {
        Ok(self.tree.proof(indices).to_bytes())
    }

    pub fn get_verifier_proof(&mut self) -> Result<Vec<u8>> {
        self.get_proof(&[0])
    }

    pub fn get_relying_party_proof(&mut self) -> Result<Vec<u8>> {
        self.get_proof(&[1])
    }

    fn prove_subtree(tree_root: [u8; 32], proof: Vec<u8>, value: [u8; 32], subtree_index: usize) -> Result<bool> {
        let proof = MerkleProof::<Sha256>::from_bytes(proof.as_slice())?;
        let valid_proof: bool = proof.verify(tree_root, &[subtree_index], &[value], 2);
        Ok(valid_proof)
    }

    pub fn prove_verifier(tree_root: [u8; 32], proof: Vec<u8>, value: [u8; 32]) -> Result<bool> {
        Self::prove_subtree(tree_root, proof, value, 0)
    }

    pub fn prove_relying_party(tree_root: [u8; 32], proof: Vec<u8>, value: [u8; 32]) -> Result<bool> {
        Self::prove_subtree(tree_root, proof, value, 1)
    }
}
