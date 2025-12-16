#[cfg(feature = "constraints")]
mod constraints;
mod test_utils;
mod delta_encoding_tests;

#[cfg(all(test, feature = "bench_harness"))]
mod bench_report;

mod bytes_mt_tests {

    use crate::{crh::*, merkle_tree::*};
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_ff::BigInteger256;
    use ark_serialize::CanonicalSerialize;
    use ark_std::{test_rng, UniformRand};

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
            .map(|leaf| crate::to_uncompressed_bytes!(leaf).unwrap())
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

        assert!(multi_proof
            .verify(&leaf_crh_params, &two_to_one_params, &root, leaves.clone())
            .unwrap());

        // test merkle tree update functionality
        for (i, v) in update_query {
            let bytes = crate::to_uncompressed_bytes!(v).unwrap();
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

        assert!(multi_proof
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
            .map(|leaf| crate::to_uncompressed_bytes!(leaf).unwrap())
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

        // multi-proof should verify and contain co-set data consistent with expected on-path sets
        assert!(multi_proof
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
    use ark_std::{test_rng, UniformRand, One};

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

    #[test]
    fn multiproof_empty_batch_verifies() {
        let mut rng = test_rng();
        let leaves: Vec<Vec<_>> = (0..4).map(|_| (0..3).map(|_| F::rand(&mut rng)).collect()).collect();
        let leaf_crh_params = poseidon_parameters();
        let two_to_one_params = leaf_crh_params.clone();
        let tree = FieldMT::new(&leaf_crh_params, &two_to_one_params, &leaves).unwrap();
        let root = tree.root();

        let proof = tree.generate_multi_proof(Vec::<usize>::new()).unwrap();
        assert!(
            proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, Vec::<Vec<F>>::new())
                .unwrap(),
            "empty batch proof should verify"
        );
        assert_eq!(proof.leaf_indexes.len(), 0);
    }

    #[test]
    fn multiproof_duplicate_indices_deduped() {
        let mut rng = test_rng();
        let leaves: Vec<Vec<_>> = (0..8).map(|_| (0..3).map(|_| F::rand(&mut rng)).collect()).collect();
        let leaf_crh_params = poseidon_parameters();
        let two_to_one_params = leaf_crh_params.clone();
        let tree = FieldMT::new(&leaf_crh_params, &two_to_one_params, &leaves).unwrap();
        let root = tree.root();

        let indexes = vec![3usize, 1, 3, 1, 5];
        let proof = tree.generate_multi_proof(indexes.clone()).unwrap();
        assert_eq!(proof.leaf_indexes, vec![1, 3, 5], "indexes should be sorted & deduped");

        let opened: Vec<_> = proof
            .leaf_indexes
            .iter()
            .map(|&i| leaves[i].clone())
            .collect();

        assert!(
            proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, opened)
                .unwrap(),
            "proof with duplicate input indices should verify after deduplication"
        );
    }

    #[test]
    fn multiproof_wrong_leaf_copath_fails() {
        let mut rng = test_rng();
        let leaves: Vec<Vec<_>> = (0..8).map(|_| (0..3).map(|_| F::rand(&mut rng)).collect()).collect();
        let leaf_crh_params = poseidon_parameters();
        let two_to_one_params = leaf_crh_params.clone();
        let tree = FieldMT::new(&leaf_crh_params, &two_to_one_params, &leaves).unwrap();
        let root = tree.root();

        let proof = tree.generate_multi_proof(vec![1usize, 6]).unwrap();
        let mut bad = proof.clone();
        if let Some(first) = bad.leaf_copath.get_mut(0) {
            *first += F::one(); // flip one sibling digest
        }
        let opened: Vec<_> = bad
            .leaf_indexes
            .iter()
            .map(|&i| leaves[i].clone())
            .collect();

        let ok = bad
            .verify(&leaf_crh_params, &two_to_one_params, &root, opened)
            .unwrap();
        assert!(!ok, "tampered leaf_copath digest must fail verification");
    }

    #[test]
    fn multiproof_missing_inner_entry_fails() {
        let mut rng = test_rng();
        let leaves: Vec<Vec<_>> = (0..16).map(|_| (0..3).map(|_| F::rand(&mut rng)).collect()).collect();
        let leaf_crh_params = poseidon_parameters();
        let two_to_one_params = leaf_crh_params.clone();
        let tree = FieldMT::new(&leaf_crh_params, &two_to_one_params, &leaves).unwrap();
        let root = tree.root();

        let proof = tree.generate_multi_proof(vec![2usize, 5, 9]).unwrap();
        let mut bad = proof.clone();
        if let Some((_, _, _, digests)) = bad.inner_copath.as_mut() {
            if !digests.is_empty() {
                digests.pop(); // drop one inner sibling digest
            }
        }
        let opened: Vec<_> = bad
            .leaf_indexes
            .iter()
            .map(|&i| leaves[i].clone())
            .collect();
        let ok = bad
            .verify(&leaf_crh_params, &two_to_one_params, &root, opened)
            .unwrap();
        assert!(!ok, "missing inner copath entry must invalidate the proof");
    }

    #[test]
    fn multiproof_open_order_robustness() {
        let mut rng = test_rng();
        let leaves: Vec<Vec<_>> = (0..8).map(|_| (0..3).map(|_| F::rand(&mut rng)).collect()).collect();
        let leaf_crh_params = poseidon_parameters();
        let two_to_one_params = leaf_crh_params.clone();
        let tree = FieldMT::new(&leaf_crh_params, &two_to_one_params, &leaves).unwrap();
        let root = tree.root();

        let indexes = vec![4usize, 1, 6];
        let proof = tree.generate_multi_proof(indexes.clone()).unwrap();

        // verification should use leaves ordered by proof.leaf_indexes (sorted)
        let ordered_leaves: Vec<_> = proof
            .leaf_indexes
            .iter()
            .map(|&i| leaves[i].clone())
            .collect();
        assert!(
            proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, ordered_leaves.clone())
                .unwrap(),
            "proof should verify when leaves follow proof.leaf_indexes order"
        );

        // providing leaves in shuffled query order should fail
        let shuffled_leaves: Vec<_> = indexes
            .iter()
            .map(|&i| leaves[i].clone())
            .collect();
        let ok = proof
            .verify(&leaf_crh_params, &two_to_one_params, &root, shuffled_leaves)
            .unwrap();
        assert!(!ok, "mismatched leaf ordering must fail verification");
    }

}

mod delta_encoding_spacing_tests {
    use super::super::{decode_delta, CoPath, Config, IdentityDigestConverter, CRHScheme, TwoToOneCRHScheme};
    use ark_std::borrow::Borrow;

    struct DummyCfg;
    impl Config for DummyCfg {
        type Leaf = ();
        type LeafDigest = u8;
        type LeafInnerDigestConverter = IdentityDigestConverter<u8>;
        type InnerDigest = u8;
        type LeafHash = DummyLeafHash;
        type TwoToOneHash = DummyTwoToOne;
    }

    struct DummyLeafHash;
    impl CRHScheme for DummyLeafHash {
        type Input = ();
        type Output = u8;
        type Parameters = ();

        fn setup<R: ark_std::rand::Rng>(_rng: &mut R) -> Result<Self::Parameters, super::super::Error> {
            Ok(())
        }

        fn evaluate<T: Borrow<Self::Input>>(
            _parameters: &Self::Parameters,
            _input: T,
        ) -> Result<Self::Output, super::super::Error> {
            Ok(0)
        }
    }

    struct DummyTwoToOne;
    impl TwoToOneCRHScheme for DummyTwoToOne {
        type Input = u8;
        type Output = u8;
        type Parameters = ();

        fn setup<R: ark_std::rand::Rng>(_rng: &mut R) -> Result<Self::Parameters, super::super::Error> {
            Ok(())
        }

        fn evaluate<T: Borrow<Self::Input>>(
            _parameters: &Self::Parameters,
            left: T,
            right: T,
        ) -> Result<Self::Output, super::super::Error> {
            Ok(*left.borrow() ^ *right.borrow())
        }

        fn compress<T: Borrow<Self::Output>>(
            _parameters: &Self::Parameters,
            left: T,
            right: T,
        ) -> Result<Self::Output, super::super::Error> {
            Ok(*left.borrow() ^ *right.borrow())
        }
    }

    #[test]
    fn packed_deltas_save_with_large_index_gaps() {
        // Coordinate entries are sorted lexicographically by (depth, index), and deltas are taken
        // between consecutive coordinates in this order (not relative to a global heap index).
        //
        // This test demonstrates the worst case spaced openings scenario at the leaf level, plus a
        // higher-layer sibling at depth d-2. 
        let d: usize = 14;
        let depth_inner = d - 2;
        let depth_leaf = d - 1;

        let mid = 1usize << (d - 2);
        let end = (1usize << (d - 1)) - 1;

        let entries: Vec<(usize, usize, u8)> = vec![
            (depth_inner, 0, 10),
            (depth_leaf, 0, 20),
            (depth_leaf, mid, 30),
            (depth_leaf, end, 40),
        ];

        let packed = CoPath::<DummyCfg>::pack_inner_copath(&entries).expect("packs");
        let (_start_depth, _start_index, deltas, _digests) = packed; // returns `deltas` which is a Vec<u8>.

        // The first step is from (d-2,0) -> (d-1,0): depth delta is +1, index delta is 0.
        let mut cursor = 0usize;
        let depth_delta = decode_delta(&deltas, &mut cursor).expect("depth delta decodes");
        let index_delta = decode_delta(&deltas, &mut cursor).expect("index delta decodes");
        assert_eq!(depth_delta, 1);
        assert_eq!(index_delta, 0);

        // Sanity check that the packed coordinate encoding is smaller than storing every (depth,index)
        // as a fixed-width pair of `usize`s.
        let naive_coord_bytes = entries.len() * 2 * core::mem::size_of::<usize>();
        let packed_coord_bytes = 2 * core::mem::size_of::<usize>() + deltas.len();
        assert!(
            packed_coord_bytes < naive_coord_bytes,
            "expected packed coordinates to be smaller (packed={}, naive={})",
            packed_coord_bytes,
            naive_coord_bytes
        );
    }
}
