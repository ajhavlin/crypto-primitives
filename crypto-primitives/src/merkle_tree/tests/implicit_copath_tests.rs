use crate::{
    crh::poseidon,
    merkle_tree::{
        tests::test_utils::poseidon_parameters,
        Config, IdentityDigestConverter, MerkleTree,
    },
};
use ark_std::{test_rng, One, UniformRand};

type F = ark_ed_on_bls12_381::Fr;
type H = poseidon::CRH<F>;
type TwoToOneH = poseidon::TwoToOneCRH<F>;

struct FieldMTConfig;
impl Config for FieldMTConfig {
    type Leaf = [F];
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = H;
    type TwoToOneHash = TwoToOneH;
}
type FieldMT = MerkleTree<FieldMTConfig>;

fn make_tree(num_leaves: usize) -> (FieldMT, Vec<Vec<F>>) {
    let mut rng = test_rng();
    let params = poseidon_parameters();
    let leaves: Vec<Vec<F>> = (0..num_leaves)
        .map(|_| (0..3).map(|_| F::rand(&mut rng)).collect())
        .collect();
    let tree = FieldMT::new(&params, &params, &leaves).unwrap();
    (tree, leaves)
}

#[test]
fn implicit_proof_verifies_single_leaf() {
    let (tree, leaves) = make_tree(8);
    let params = poseidon_parameters();
    let root = tree.root();

    for i in 0..leaves.len() {
        let proof = tree.generate_implicit_multi_proof([i]).unwrap();
        let ok = proof
            .verify(&params, &params, &root, tree.height(), [leaves[i].clone()])
            .unwrap();
        assert!(ok, "single-leaf implicit proof must verify for index {i}");
    }
}

#[test]
fn implicit_proof_verifies_full_batch() {
    let (tree, leaves) = make_tree(16);
    let params = poseidon_parameters();
    let root = tree.root();

    let proof = tree
        .generate_implicit_multi_proof(0..leaves.len())
        .unwrap();
    assert!(
        proof
            .verify(&params, &params, &root, tree.height(), leaves.clone())
            .unwrap(),
        "full-batch implicit proof must verify"
    );
    // full batch: no inner copath elements needed — every sibling is on-path
    assert_eq!(
        proof.inner_copath.len(),
        0,
        "full-batch inner copath must be empty"
    );
}

#[test]
fn implicit_proof_matches_coset_proof_node_count() {
    // The number of digests transmitted should be identical to the CoPath counterpart,
    // since both encode the same copath set — just without coordinates in ImplicitCoPath.
    let (tree, _leaves) = make_tree(32);
    for idxs in &[
        vec![0usize, 1, 2, 3],
        vec![0, 7, 15, 31],
        vec![5, 11, 23],
    ] {
        let implicit = tree.generate_implicit_multi_proof(idxs.iter().copied()).unwrap();
        let coset = tree.generate_multi_proof(idxs.iter().copied()).unwrap();

        let coset_inner_nodes = coset
            .inner_copath
            .as_ref()
            .map(|(_, _, _, d)| d.len())
            .unwrap_or(0);

        assert_eq!(
            implicit.inner_copath.len(),
            coset_inner_nodes,
            "inner node count must match for indexes {:?}",
            idxs
        );
        assert_eq!(
            implicit.leaf_copath.len(),
            coset.leaf_copath.len(),
            "leaf copath length must match for indexes {:?}",
            idxs
        );
    }
}

#[test]
fn implicit_proof_wrong_root_fails() {
    let (tree, leaves) = make_tree(8);
    let params = poseidon_parameters();
    let wrong_root = tree.root() + F::one();

    let proof = tree.generate_implicit_multi_proof([2usize, 5]).unwrap();
    let opened: Vec<_> = proof.leaf_indexes.iter().map(|&i| leaves[i].clone()).collect();
    let ok = proof
        .verify(&params, &params, &wrong_root, tree.height(), opened)
        .unwrap();
    assert!(!ok, "wrong root must fail verification");
}

#[test]
fn implicit_proof_tampered_inner_digest_fails() {
    let (tree, leaves) = make_tree(16);
    let params = poseidon_parameters();
    let root = tree.root();

    let proof = tree.generate_implicit_multi_proof([1usize, 6, 10]).unwrap();
    let mut bad = proof.clone();
    if let Some(d) = bad.inner_copath.get_mut(0) {
        *d += F::one();
    }
    let opened: Vec<_> = bad.leaf_indexes.iter().map(|&i| leaves[i].clone()).collect();
    let ok = bad.verify(&params, &params, &root, tree.height(), opened).unwrap();
    assert!(!ok, "tampered inner digest must fail verification");
}

#[test]
fn implicit_proof_extra_digest_fails() {
    let (tree, leaves) = make_tree(16);
    let params = poseidon_parameters();
    let root = tree.root();

    let proof = tree.generate_implicit_multi_proof([3usize, 9]).unwrap();
    let mut bad = proof.clone();
    bad.inner_copath.push(F::one()); // one spurious digest
    let opened: Vec<_> = bad.leaf_indexes.iter().map(|&i| leaves[i].clone()).collect();
    let ok = bad.verify(&params, &params, &root, tree.height(), opened).unwrap();
    assert!(!ok, "extra inner digest must fail verification");
}

#[test]
fn implicit_proof_missing_inner_digest_fails() {
    let (tree, leaves) = make_tree(16);
    let params = poseidon_parameters();
    let root = tree.root();

    let proof = tree.generate_implicit_multi_proof([2usize, 5, 9]).unwrap();
    let mut bad = proof.clone();
    if !bad.inner_copath.is_empty() {
        bad.inner_copath.pop();
    }
    let opened: Vec<_> = bad.leaf_indexes.iter().map(|&i| leaves[i].clone()).collect();
    let ok = bad.verify(&params, &params, &root, tree.height(), opened).unwrap();
    assert!(!ok, "missing inner digest must fail verification");
}

#[test]
fn implicit_proof_wrong_tree_height_fails() {
    let (tree, leaves) = make_tree(8);
    let params = poseidon_parameters();
    let root = tree.root();

    let proof = tree.generate_implicit_multi_proof([0usize, 3]).unwrap();
    let opened: Vec<_> = proof.leaf_indexes.iter().map(|&i| leaves[i].clone()).collect();
    // supply wrong expected height
    let ok = proof
        .verify(&params, &params, &root, tree.height() + 1, opened)
        .unwrap();
    assert!(!ok, "mismatched tree height must fail verification");
}

#[test]
fn implicit_proof_duplicate_indices_deduped() {
    let (tree, leaves) = make_tree(8);
    let params = poseidon_parameters();
    let root = tree.root();

    let proof = tree
        .generate_implicit_multi_proof([2usize, 2, 5, 5, 5])
        .unwrap();
    assert_eq!(proof.leaf_indexes, vec![2, 5], "duplicates must be deduped");

    let opened: Vec<_> = proof.leaf_indexes.iter().map(|&i| leaves[i].clone()).collect();
    assert!(
        proof.verify(&params, &params, &root, tree.height(), opened).unwrap(),
        "deduped implicit proof must verify"
    );
}
