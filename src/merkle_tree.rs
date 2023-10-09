use anyhow::Result;
use rs_merkle::{algorithms::Sha256, Hasher, MerkleProof, MerkleTree};

pub fn build_evidence() -> Result<([u8; 32], Vec<u8>)> {
    let leaf_values = ["a", "b", "c", "d", "e", "f"];
    let leaves: Vec<[u8; 32]> = leaf_values
        .iter()
        .map(|x| Sha256::hash(x.as_bytes()))
        .collect();

    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let indices_to_prove = vec![3, 4];
    let leaves_to_prove = leaves.get(3..5).unwrap();
    let merkle_proof = merkle_tree.proof(&indices_to_prove);
    let merkle_root = merkle_tree.root().unwrap();
    // Serialize proof to pass it to the client
    let proof_bytes = merkle_proof.to_bytes();

    // Parse proof back on the client
    let proof = MerkleProof::<Sha256>::try_from(proof_bytes.clone())?;
    proof.verify(
        merkle_root,
        &indices_to_prove,
        leaves_to_prove,
        leaves.len(),
    );

    Ok((merkle_root, proof_bytes))
}

pub fn is_valid(merkle_root: Vec<u8>, proof_bytes: Vec<u8>) -> bool {
    let leaf_values = ["a", "b", "c", "d", "e", "f"];
    let leaves: Vec<[u8; 32]> = leaf_values
        .iter()
        .map(|x| Sha256::hash(x.as_bytes()))
        .collect();

    let indices_to_prove = vec![3, 4];
    let leaves_to_prove = leaves.get(3..5).unwrap();

    // Parse proof back on the client
    let proof = MerkleProof::<Sha256>::try_from(proof_bytes.clone()).unwrap();
    let merkle_root: [u8; 32] = merkle_root.try_into().unwrap();
    proof.verify(
        merkle_root,
        &indices_to_prove,
        leaves_to_prove,
        leaves.len(),
    )
}

#[cfg(test)]
mod tests {
    use crate::merkle_tree::is_valid;

    use super::build_evidence;

    #[test]
    fn it_works() {
        let (merkle_root, proof_bytes) = build_evidence().unwrap();
        assert!(is_valid(merkle_root, proof_bytes));
    }
}
