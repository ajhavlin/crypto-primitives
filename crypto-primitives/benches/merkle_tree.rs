#[macro_use]
extern crate criterion;

static NUM_LEAVES: i32 = 1 << 20;

mod bytes_mt_benches {
    use ark_crypto_primitives::crh::*;
    use ark_crypto_primitives::merkle_tree::*;
    use ark_crypto_primitives::to_uncompressed_bytes;
    use ark_ff::BigInteger256;
    use ark_serialize::CanonicalSerialize;
    use ark_std::{test_rng, UniformRand};
    use criterion::Criterion;
    use std::borrow::Borrow;

    use crate::NUM_LEAVES;

    type LeafH = sha2::Sha256;
    type CompressH = sha2::Sha256;

    struct Sha256MerkleTreeParams;

    impl Config for Sha256MerkleTreeParams {
        type Leaf = [u8];

        type LeafDigest = <LeafH as CRHScheme>::Output;
        type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
        type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;

        type LeafHash = LeafH;
        type TwoToOneHash = CompressH;
    }
    type Sha256MerkleTree = MerkleTree<Sha256MerkleTreeParams>;

    pub fn merkle_tree_create(c: &mut Criterion) {
        let mut rng = test_rng();
        let leaves: Vec<_> = (0..NUM_LEAVES)
            .map(|_| {
                let rnd = BigInteger256::rand(&mut rng);
                to_uncompressed_bytes!(rnd).unwrap()
            })
            .collect();
        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng)
            .unwrap()
            .clone();
        c.bench_function("Merkle Tree Create (Leaves as [u8])", move |b| {
            b.iter(|| {
                Sha256MerkleTree::new(
                    &leaf_crh_params.clone(),
                    &two_to_one_params.clone(),
                    &leaves,
                )
                .unwrap();
            })
        });
    }

    pub fn merkle_tree_generate_single_opening(c: &mut Criterion) {
        let mut rng = test_rng();
        let leaves: Vec<_> = (0..NUM_LEAVES)
            .map(|_| {
                let rnd = BigInteger256::rand(&mut rng);
                to_uncompressed_bytes!(rnd).unwrap()
            })
            .collect();
        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng)
            .unwrap()
            .clone();

        let tree_height = leaves.len().trailing_zeros() as usize + 1;
        let scheme = Sha256MerkleTree::blank(
            &leaf_crh_params.clone(),
            &two_to_one_params.clone(),
            tree_height,
        )
        .unwrap();
        let committed = scheme.commit(&leaves).unwrap();
        c.bench_function(
            "Merkle Tree Generate Single Opening (Leaves as [u8])",
            move |b| {
                b.iter(|| {
                    for (i, _) in leaves.iter().enumerate() {
                        committed.open([i]);
                    }
                })
            },
        );
    }

    pub fn merkle_tree_verify_single_opening(c: &mut Criterion) {
        let mut rng = test_rng();
        let leaves: Vec<_> = (0..NUM_LEAVES)
            .map(|_| {
                let rnd = BigInteger256::rand(&mut rng);
                to_uncompressed_bytes!(rnd).unwrap()
            })
            .collect();
        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng)
            .unwrap()
            .clone();

        let tree_height = leaves.len().trailing_zeros() as usize + 1;
        let scheme = Sha256MerkleTree::blank(
            &leaf_crh_params.clone(),
            &two_to_one_params.clone(),
            tree_height,
        )
        .unwrap();
        let committed = scheme.commit(&leaves).unwrap();
        let root = committed.root();
        let openings_and_proofs: Vec<_> = leaves
            .iter()
            .enumerate()
            .map(|(i, leaf)| {
                (
                    Opening::new(vec![i], vec![leaf.clone()]),
                    committed.open([i]),
                )
            })
            .collect();

        c.bench_function(
            "Merkle Tree Verify Single Opening (Leaves as [u8])",
            move |b| {
                b.iter(|| {
                    for (opening, proof) in &openings_and_proofs {
                        scheme.check(&root, opening, proof);
                    }
                })
            },
        );
    }

    pub fn merkle_tree_generate_multi_proof(c: &mut Criterion) {
        let mut rng = test_rng();
        let leaves: Vec<_> = (0..NUM_LEAVES)
            .map(|_| {
                let rnd = BigInteger256::rand(&mut rng);
                to_uncompressed_bytes!(rnd).unwrap()
            })
            .collect();
        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng)
            .unwrap()
            .clone();

        let tree_height = leaves.len().trailing_zeros() as usize + 1;
        let scheme = Sha256MerkleTree::blank(
            &leaf_crh_params.clone(),
            &two_to_one_params.clone(),
            tree_height,
        )
        .unwrap();
        let committed = scheme.commit(&leaves).unwrap();
        c.bench_function(
            "Merkle Tree Generate Multi Proof (Leaves as [u8])",
            move |b| {
                b.iter(|| {
                    committed.open(0..leaves.len());
                })
            },
        );
    }

    pub fn merkle_tree_verify_multi_proof(c: &mut Criterion) {
        let mut rng = test_rng();
        let leaves: Vec<_> = (0..NUM_LEAVES)
            .map(|_| {
                let rnd = BigInteger256::rand(&mut rng);
                to_uncompressed_bytes!(rnd).unwrap()
            })
            .collect();
        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng)
            .unwrap()
            .clone();

        let tree_height = leaves.len().trailing_zeros() as usize + 1;
        let scheme = Sha256MerkleTree::blank(
            &leaf_crh_params.clone(),
            &two_to_one_params.clone(),
            tree_height,
        )
        .unwrap();

        let committed = scheme.commit(&leaves).unwrap();
        let root = committed.root();
        let indices: Vec<_> = (0..leaves.len()).collect();
        let opening = Opening::new(indices.clone(), leaves.clone());
        let multi_proof = committed.open(indices);

        c.bench_function(
            "Merkle Tree Verify Multi Proof (Leaves as [u8])",
            move |b| b.iter(|| scheme.check(&root, &opening, &multi_proof)),
        );
    }

    criterion_group! {
        name = mt_create;
        config = Criterion::default().sample_size(100);
        targets = merkle_tree_create
    }

    criterion_group! {
        name = mt_proof;
        config = Criterion::default().sample_size(100);
        targets = merkle_tree_generate_single_opening, merkle_tree_generate_multi_proof
    }

    criterion_group! {
        name = mt_verify;
        config = Criterion::default().sample_size(10);
        targets = merkle_tree_verify_single_opening, merkle_tree_verify_multi_proof
    }
}

criterion_main!(
    bytes_mt_benches::mt_create,
    bytes_mt_benches::mt_proof,
    bytes_mt_benches::mt_verify
);
