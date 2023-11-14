use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};

/// The Evidence trait for implementing custom device Evidence.
pub trait Evidence {
    /// Return the data in this evidence as bytes.
    ///
    /// Your [Evidence] implementation should convert all the fields to bytes. This
    /// should be done in the same way in which the server will carry out the task. If
    /// these don't match, verification will fail. Therefore, it is suggested to
    /// use the same [Evidence] implementation on the verification server and the
    /// client device.
    ///
    /// # Example
    /// ```
    /// pub struct DefaultEvidence {
    ///     name: String,
    ///     key: [u8; 64],
    /// }
    ///
    /// impl Evidence for DefaultEvidence {
    ///     fn to_leaves(&self) -> Vec<Vec<u8>> {
    ///         vec![self.name.clone().into_bytes(), self.key.into()]
    ///     }
    /// }
    /// ```
    fn to_leaves(&self) -> Vec<Vec<u8>>;

    fn size(&self) -> usize;

    fn get_leaf(&self, index: usize) -> [u8; 32] {
        let leaf_values = self.to_leaves();
        let leaves: Vec<[u8; 32]> = leaf_values.iter().map(|x| Sha256::hash(x)).collect();
        leaves[index]
    }

    /// Return the root of the merkle tree of the evidence.
    ///
    /// This method uses the bytes, from [`Self::to_leaves()`], and then
    /// converts all the leaves into hashes and creates a Merkle Tree out of it.
    /// The function then returns the root of the Merkle Tree.
    fn build_root(&self) -> [u8; 32] {
        let leaf_values = self.to_leaves();
        let leaves: Vec<[u8; 32]> = leaf_values.iter().map(|x| Sha256::hash(x)).collect();

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let merkle_root = merkle_tree.root().unwrap();

        merkle_root
    }

    /// Create a proof for some fields in the evidence.
    fn build_proof(&self, index: usize) -> Vec<u8> {
        let leaf_values = self.to_leaves();
        let leaves: Vec<[u8; 32]> = leaf_values.iter().map(|x| Sha256::hash(x)).collect();
        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let proof = merkle_tree.proof(&[index]);
        proof.to_bytes()
    }
}

pub struct TestEvidence {
    name: String,
    key: [u8; 64],
}

impl Default for TestEvidence {
    fn default() -> Self {
        Self {
            name: Default::default(),
            key: [
                0, 0, 0, 0, 1, 1, 1, 2, 1, 2, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 1, 1, 1, 1,
            ],
        }
    }
}

impl Evidence for TestEvidence {
    fn to_leaves(&self) -> Vec<Vec<u8>> {
        vec![self.name.clone().into_bytes(), self.key.into()]
    }

    fn size(&self) -> usize {
        return 2;
    }
}

pub struct TestVerifierEvidence {
    name: String,
    key: [u8; 64],
    version: String,
}

impl Default for TestVerifierEvidence {
    fn default() -> Self {
        Self {
            name: Default::default(),
            key: [
                0, 0, 0, 0, 1, 1, 1, 2, 1, 2, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 1, 1, 1, 1,
            ],
            version: String::from("0.0.1"),
        }
    }
}

impl Evidence for TestVerifierEvidence {
    fn to_leaves(&self) -> Vec<Vec<u8>> {
        vec![
            self.name.clone().into(),
            self.key.into(),
            self.version.clone().into(),
        ]
    }

    fn size(&self) -> usize {
        return 2;
    }
}
