#[cfg(feature = "constraints")]
mod constraints;
mod test_utils;

mod bench_report;

mod bytes_mt_tests {

    use crate::{crh::*, merkle_tree::*};
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_ff::BigInteger256;
    use ark_serialize::CanonicalSerialize;
    use ark_std::{iter::zip, test_rng, UniformRand};

    #[derive(Clone)]
    pub(super) struct Window4x256;
    impl pedersen::Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type LeafH = pedersen::CRH<JubJub, Window4x256>;
    type CompressH = pedersen::TwoToOneCRH<JubJub, Window4x256>;

    struct JubJubMerkleTreeParams;

    impl Config for JubJubMerkleTreeParams {
        type Leaf = [u8];

        type LeafDigest = <LeafH as CRHScheme>::Output;
        type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
        type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;

        type LeafHash = LeafH;
        type TwoToOneHash = CompressH;
    }
    type JubJubMerkleTree = MerkleTree<JubJubMerkleTreeParams>;

    /// Pedersen only takes bytes as leaf, so we serialise leaves canonically into bytes.
    fn merkle_tree_test<L: CanonicalSerialize>(leaves: &[L], update_query: &[(usize, L)]) -> () {
        let mut rng = ark_std::test_rng();

        let mut leaves: Vec<Vec<u8>> = leaves
            .iter()
            .map(|leaf| {
                let mut bytes = Vec::new();
                leaf.serialize_uncompressed(&mut bytes).unwrap();
                bytes
            })
            .collect();

        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        let mut tree =
            JubJubMerkleTree::new(&leaf_crh_params, &two_to_one_params, &leaves).unwrap();

        let mut root = tree.root();
        // test merkle tree functionality without update
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap());
        }

        // test the merkle tree multi-proof functionality
        let mut multi_proof = tree
            .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        let mut coset_multi_proof = tree
            .generate_multi_proof_v2((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        assert!(multi_proof
            .verify(&leaf_crh_params, &two_to_one_params, &root, leaves.clone())
            .unwrap());
        assert!(coset_multi_proof
            .verify(&leaf_crh_params, &two_to_one_params, &root, leaves.clone())
            .unwrap());

        // test merkle tree update functionality
        for (i, v) in update_query {
            let mut bytes = Vec::new();
            v.serialize_uncompressed(&mut bytes).unwrap();
            tree.update(*i, &bytes).unwrap();
            leaves[*i] = bytes.clone();
        }
        // update the root
        root = tree.root();
        // verify again
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap());
        }

        // test the merkle tree multi-proof functionality again
        multi_proof = tree
            .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();
        coset_multi_proof = tree
            .generate_multi_proof_v2((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        assert!(multi_proof
            .verify(&leaf_crh_params, &two_to_one_params, &root, leaves.clone())
            .unwrap());
        assert!(coset_multi_proof
            .verify(&leaf_crh_params, &two_to_one_params, &root, leaves.clone())
            .unwrap());
    }

    #[test]
    fn good_root_test() {
        let mut rng = test_rng();

        let mut leaves = Vec::new();
        for _ in 0..2u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }
        merkle_tree_test(
            &leaves,
            &vec![
                (0, BigInteger256::rand(&mut rng)),
                (1, BigInteger256::rand(&mut rng)),
            ],
        );

        let mut leaves = Vec::new();
        for _ in 0..4u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }
        merkle_tree_test(&leaves, &vec![(3, BigInteger256::rand(&mut rng))]);

        let mut leaves = Vec::new();
        for _ in 0..128u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }
        merkle_tree_test(
            &leaves,
            &vec![
                (2, BigInteger256::rand(&mut rng)),
                (3, BigInteger256::rand(&mut rng)),
                (5, BigInteger256::rand(&mut rng)),
                (111, BigInteger256::rand(&mut rng)),
                (127, BigInteger256::rand(&mut rng)),
            ],
        );
    }

    #[test]
    fn multi_proof_dissection_test() {
        let mut rng = test_rng();

        let mut leaves = Vec::new();
        for _ in 0..8u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }
        assert_eq!(leaves.len(), 8);

        let serialized_leaves: Vec<Vec<u8>> = leaves
            .iter()
            .map(|leaf| {
                let mut bytes = Vec::new();
                leaf.serialize_uncompressed(&mut bytes).unwrap();
                bytes
            })
            .collect();

        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        let tree = JubJubMerkleTree::new(&leaf_crh_params, &two_to_one_params, &serialized_leaves)
            .unwrap();

        let mut proofs = Vec::with_capacity(leaves.len());

        for (i, _) in leaves.iter().enumerate() {
            proofs.push(tree.generate_proof(i).unwrap());
        }

        let multi_proof = tree
            .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        let coset_multi_proof = tree
            .generate_multi_proof_v2((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        // test compression theretical prefix lengths for size 8 Tree:
        // we should send 6 hashes instead of 2*8 = 16
        let theoretical_prefix_lengths = vec![0, 2, 1, 2, 0, 2, 1, 2];

        for (comp_len, exp_len) in zip(
            &multi_proof.auth_paths_prefix_lenghts,
            &theoretical_prefix_lengths,
        ) {
            assert_eq!(comp_len, exp_len);
        }

        // test that the compressed paths can expand to expected len
        for (prefix_len, suffix) in zip(
            &multi_proof.auth_paths_prefix_lenghts,
            &multi_proof.auth_paths_suffixes,
        ) {
            assert_eq!(prefix_len + suffix.len(), proofs[0].auth_path.len());
        }

        assert!(coset_multi_proof
            .verify(
                &leaf_crh_params,
                &two_to_one_params,
                &tree.root(),
                serialized_leaves.clone()
            )
            .unwrap());
    }
}

mod field_mt_tests {
    use crate::{
        crh::poseidon,
        merkle_tree::{
            tests::test_utils::poseidon_parameters, Config, IdentityDigestConverter, MerkleTree,
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

    fn merkle_tree_test(leaves: &[Vec<F>], update_query: &[(usize, Vec<F>)]) -> () {
        let mut leaves = leaves.to_vec();
        let leaf_crh_params = poseidon_parameters();
        let two_to_one_params = leaf_crh_params.clone();

        let mut tree = FieldMT::new(&leaf_crh_params, &two_to_one_params, &leaves).unwrap();

        let mut root = tree.root();

        // test merkle tree functionality without update
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap());
        }

        // test the merkle tree multi-proof functionality
        let mut multi_proof = tree
            .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        assert!(multi_proof
            .verify(&leaf_crh_params, &two_to_one_params, &root, leaves.clone())
            .unwrap());

        {
            // wrong root should lead to error but do not panic
            let wrong_root = root + F::one();
            let proof = tree.generate_proof(0).unwrap();
            assert!(!proof
                .verify(
                    &leaf_crh_params,
                    &two_to_one_params,
                    &wrong_root,
                    leaves[0].as_slice()
                )
                .unwrap());

            // test the merkle tree multi-proof functionality
            let multi_proof = tree
                .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
                .unwrap();

            assert!(!multi_proof
                .verify(
                    &leaf_crh_params,
                    &two_to_one_params,
                    &wrong_root,
                    leaves.clone()
                )
                .unwrap());
        }

        // test merkle tree update functionality
        for (i, v) in update_query {
            tree.update(*i, v).unwrap();
            leaves[*i] = v.to_vec();
        }

        // update the root
        root = tree.root();

        // verify again
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap());
        }

        multi_proof = tree
            .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        assert!(multi_proof
            .verify(&leaf_crh_params, &two_to_one_params, &root, leaves.clone())
            .unwrap());
    }

    #[test]
    fn multiproof_prefix_encoding_sanity() {
        use ark_std::collections::BTreeSet;

        let leaves: Vec<Vec<_>> = (0..32u64).map(|i| vec![F::from(i)]).collect();
        let leaf_crh_params = poseidon_parameters();
        let two_to_one_params = leaf_crh_params.clone();
        let tree = FieldMT::new(&leaf_crh_params, &two_to_one_params, &leaves).unwrap();

        let query_indexes = vec![9usize, 0, 12, 5, 3, 3, 17, 24, 31, 0];
        let multi_proof = tree
            .generate_multi_proof(query_indexes.clone())
            .unwrap();

        let sorted_unique: Vec<_> = query_indexes
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        let mut prev_path: Vec<F> = Vec::new();
        let mut expected_prefix_lengths = Vec::new();
        let mut expected_suffixes: Vec<Vec<F>> = Vec::new();
        let mut expected_suffix_total = 0usize;

        for &index in &sorted_unique {
            let path = tree.generate_proof(index).unwrap().auth_path;
            let prefix_len = prev_path
                .iter()
                .zip(path.iter())
                .take_while(|(a, b)| a == b)
                .count();
            let suffix = path[prefix_len..].to_vec();
            expected_suffix_total += suffix.len();
            expected_prefix_lengths.push(prefix_len);
            expected_suffixes.push(suffix);
            prev_path = path;
        }

        let actual_suffix_total: usize = multi_proof
            .auth_paths_suffixes
            .iter()
            .map(|suffix| suffix.len())
            .sum();

        assert_eq!(multi_proof.leaf_indexes, sorted_unique);
        assert_eq!(multi_proof.auth_paths_prefix_lenghts, expected_prefix_lengths);
        assert_eq!(multi_proof.auth_paths_suffixes, expected_suffixes);
        assert_eq!(multi_proof.leaf_siblings_hashes.len(), sorted_unique.len());
        assert_eq!(
            multi_proof.leaf_siblings_hashes.len() + actual_suffix_total,
            sorted_unique.len() + expected_suffix_total
        );
    }

    #[test]
    fn good_root_test() {
        let mut rng = test_rng();
        let mut rand_leaves = || (0..3).map(|_| F::rand(&mut rng)).collect();

        let mut leaves: Vec<Vec<_>> = Vec::new();
        for _ in 0..128u8 {
            leaves.push(rand_leaves())
        }
        merkle_tree_test(
            &leaves,
            &vec![
                (2, rand_leaves()),
                (3, rand_leaves()),
                (5, rand_leaves()),
                (111, rand_leaves()),
                (127, rand_leaves()),
            ],
        )
    }
}
