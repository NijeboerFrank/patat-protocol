use patat_protocol_rs::{
    combined_evidence::CombinedEvidence,
    evidence::{Evidence, TestEvidence, TestVerifierEvidence},
};

fn main() {
    let relying_party_evidence: TestEvidence = Default::default();
    let verifier_evidence: TestVerifierEvidence = Default::default();

    let mut combined_evidence = CombinedEvidence::new(
        verifier_evidence.build_root().unwrap(),
        relying_party_evidence.build_root().unwrap(),
    );
    let relying_party_proof = combined_evidence.get_relying_party_proof();
    let verifier_proof = combined_evidence.get_verifier_proof().unwrap();

    let valid = CombinedEvidence::prove_verifier(
        combined_evidence.get_root(),
        verifier_proof,
        verifier_evidence.build_root().unwrap(),
    );
    println!("Proof is {:?}", valid);
}
