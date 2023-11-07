use std::default::Default;

use anyhow::Result;
use patat_protocol::{evidence::Evidence, evidence::TestEvidence, combined_evidence::CombinedEvidence, verifier::Verifier};
use rs_merkle::{MerkleProof, algorithms::Sha256};

fn main() -> Result<()> {
    let evidence1: TestEvidence = Default::default();
    let evidence2: TestEvidence = Default::default();

    let proof = evidence1.build_proof(0);
    println!("Proof is {:?}", proof);

    // let proof = evidence1.build_proof(1);
    // println!("Proof 2: {:?}", proof);

    let proof2 = MerkleProof::<Sha256>::try_from(proof)?;
    let leaves_to_prove = evidence1.get_leaf(0);
    let valid = proof2.verify(evidence1.build_root()?, &[0], &[leaves_to_prove], 2);

    let mut root_evidence_1 = CombinedEvidence::new();
    println!("Root of the tree {:?}", root_evidence_1.tree_root);
    root_evidence_1.insert_evidence(Box::new(evidence1));
    println!("Root of the tree {:?}", root_evidence_1.tree_root);
    let root = evidence2.build_root()?;
    root_evidence_1.insert_evidence(Box::new(evidence2));
    println!("Root of the tree {:?}", root_evidence_1.tree_root);
    
    let verifier = Verifier::new();
    verifier.prove_tree(root_evidence_1.tree_root.unwrap(), root, root.to_vec(), 2)?;

    Ok(())
}
