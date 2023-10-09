use anyhow::Result;
use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};

pub trait Evidence {
    fn to_leaves(&self) -> Vec<Vec<u8>>;

    fn build_root(&self) -> Result<[u8; 32]> {
        let leaf_values = self.to_leaves();
        let leaves: Vec<[u8; 32]> = leaf_values.iter().map(|x| Sha256::hash(x)).collect();

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let merkle_root = merkle_tree.root().unwrap();

        Ok(merkle_root)
    }
}

pub struct DefaultEvidence {
    name: String,
    key: [u8; 64],
}

impl Evidence for DefaultEvidence {
    fn to_leaves(&self) -> Vec<Vec<u8>> {
        vec![self.name.clone().into_bytes(), self.key.into()]
    }
}

impl DefaultEvidence {
    pub fn new() -> DefaultEvidence {
        DefaultEvidence {
            name: String::from("testy"),
            key: [
                0, 0, 0, 0, 1, 1, 1, 2, 1, 2, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 1, 1, 1, 1,
            ],
        }
    }
}
