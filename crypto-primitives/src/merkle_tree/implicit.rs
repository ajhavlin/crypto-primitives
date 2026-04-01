//! Coordinate-free batch Merkle membership proof.
//!
//! Both prover and verifier independently derive the positions of all required copath nodes
//! from `leaf_indexes` and `tree_height` by running [`compute_on_path`].  Only the digests are
//! transmitted, in canonical depth-then-index order.  No coordinate metadata is included in the
//! proof, so the inner copath is a plain `Vec<InnerDigest>` rather than a packed delta stream.
//!
//! # Wire format vs [`super::CoPath`]
//!
//! | Field | CoPath | ImplicitCoPath |
//! |-------|--------|----------------|
//! | `tree_height` | ✓ | ✓ |
//! | `leaf_copath` | `Vec<LeafDigest>` | `Vec<LeafDigest>` (identical) |
//! | `inner_copath` | `(start_depth, start_index, deltas, digests)` | `Vec<InnerDigest>` |
//! | `leaf_indexes` | `Vec<usize>` | `Vec<usize>` |
//!
//! The saved bytes come entirely from dropping the coordinate metadata (`start_depth`,
//! `start_index`, `deltas`).  For a tree with `h` inner layers and `n_c` copath entries the
//! saving is `2 * sizeof(usize) + (n_c - 1) * 2 * avg_delta_bytes`.

use crate::Error;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
};
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;
use ark_std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
    hash::BuildHasherDefault,
};
use hashbrown::HashMap;

use super::{
    compute_on_path, level_index, CoPath, Config, DefaultHasher, LeafParam, TwoToOneParam,
};

/// Coordinate-free batch Merkle membership proof.
///
/// See the [module-level documentation](self) for a description of the protocol and a comparison
/// with [`CoPath`].
#[derive(Derivative, CanonicalSerialize)]
#[derivative(
    Clone(bound = "P: Config"),
    Debug(bound = "P: Config"),
    Default(bound = "P: Config")
)]
pub struct ImplicitCoPath<P: Config> {
    /// Height of the tree this proof was generated from (>= 2).
    pub tree_height: usize,
    /// Leaf-layer copath digests (`B*_{d-1}`), ascending sibling index order.
    pub leaf_copath: Vec<P::LeafDigest>,
    /// Inner copath digests in canonical order: depth 1 ascending, depth 2 ascending, …
    /// No coordinates are stored; the verifier derives them from `leaf_indexes`.
    pub inner_copath: Vec<P::InnerDigest>,
    /// Leaf indexes that were opened, in ascending order.
    pub leaf_indexes: Vec<usize>,
}

impl<P: Config> Valid for ImplicitCoPath<P> {
    fn check(&self) -> Result<(), SerializationError> {
        if self.tree_height < 2 {
            return Err(SerializationError::InvalidData);
        }
        self.leaf_copath.check()?;
        self.inner_copath.check()?;
        self.leaf_indexes.check()
    }
}

impl<P: Config> CanonicalDeserialize for ImplicitCoPath<P> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let tree_height = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let leaf_copath =
            Vec::<P::LeafDigest>::deserialize_with_mode(&mut reader, compress, validate)?;
        let inner_copath =
            Vec::<P::InnerDigest>::deserialize_with_mode(&mut reader, compress, validate)?;
        let leaf_indexes = Vec::<usize>::deserialize_with_mode(&mut reader, compress, validate)?;
        if tree_height < 2 {
            return Err(SerializationError::InvalidData);
        }
        Ok(ImplicitCoPath {
            tree_height,
            leaf_copath,
            inner_copath,
            leaf_indexes,
        })
    }
}

impl<P: Config> ImplicitCoPath<P> {
    /// Verify that the leaves (supplied in `leaf_indexes` order) are at the claimed positions in
    /// the tree with root `root_hash` and height `expected_tree_height`.
    ///
    /// The verifier independently reconstructs the canonical copath order from `leaf_indexes` and
    /// `tree_height`, then consumes `inner_copath` in that order.  If the digest count does not
    /// match what the verifier derives, verification returns `Ok(false)`.
    pub fn verify<L: Borrow<P::Leaf> + Clone>(
        &self,
        leaf_hash_params: &LeafParam<P>,
        two_to_one_params: &TwoToOneParam<P>,
        root_hash: &P::InnerDigest,
        expected_tree_height: usize,
        leaves: impl IntoIterator<Item = L>,
    ) -> Result<bool, Error> {
        if self.leaf_indexes.is_empty() {
            return Err(Error::GenericError(ark_std::boxed::Box::new(
                ark_std::io::Error::new(
                    ark_std::io::ErrorKind::InvalidInput,
                    "batch proof must contain at least one leaf index",
                ),
            )));
        }

        if self.tree_height < 2 {
            return Err(Error::GenericError(ark_std::boxed::Box::new(
                ark_std::io::Error::new(
                    ark_std::io::ErrorKind::InvalidInput,
                    "tree_height must be >= 2",
                ),
            )));
        }

        if self.tree_height != expected_tree_height {
            return Ok(false);
        }

        let d = self.tree_height;
        let leaf_depth = d - 1;

        let mut leaves_iter = leaves.into_iter();
        let mut leaf_level =
            CoPath::<P>::ingest_leaves(&self.leaf_indexes, &mut leaves_iter, leaf_hash_params)?;

        let index_set: BTreeSet<usize> = self.leaf_indexes.iter().copied().collect();
        let on_path = compute_on_path(leaf_depth, &index_set);

        let expected_leaf_coset = CoPath::<P>::expected_leaf_coset(leaf_depth, &on_path);
        if !CoPath::<P>::validate_leaf_copath(
            &expected_leaf_coset,
            &self.leaf_copath,
            &mut leaf_level,
        ) {
            return Ok(false);
        }

        let mut inner_levels: Vec<BTreeMap<usize, P::InnerDigest>> =
            (0..d).map(|_| BTreeMap::new()).collect();
        let mut hash_lut: HashMap<usize, P::InnerDigest, _> =
            HashMap::with_hasher(BuildHasherDefault::<DefaultHasher>::default());

        // Consume inner_copath in canonical order: depths 1..leaf_depth, ascending index.
        let mut cursor = 0usize;
        for depth in 1..leaf_depth {
            for &path_idx in on_path[depth].iter() {
                let sibling_idx = path_idx ^ 1;
                if on_path[depth].binary_search(&sibling_idx).is_err() {
                    let digest = match self.inner_copath.get(cursor) {
                        Some(d) => d,
                        None => return Ok(false), // prover sent fewer digests than expected
                    };
                    cursor += 1;
                    inner_levels[depth].insert(sibling_idx, digest.clone());
                    let heap_idx = level_index(depth, sibling_idx);
                    hash_lut.entry(heap_idx).or_insert_with(|| digest.clone());
                }
            }
        }

        // Reject if prover sent more digests than we expected.
        if cursor != self.inner_copath.len() {
            return Ok(false);
        }

        if !CoPath::<P>::recompute_bottom_parents(
            leaf_depth,
            &on_path,
            &leaf_level,
            two_to_one_params,
            &mut hash_lut,
            &mut inner_levels,
        )? {
            return Ok(false);
        }

        if !CoPath::<P>::recompute_inner_layers(
            leaf_depth,
            &on_path,
            two_to_one_params,
            &mut hash_lut,
            &mut inner_levels,
        )? {
            return Ok(false);
        }

        match inner_levels[0].get(&0) {
            Some(h) => Ok(h == root_hash),
            None => Ok(false),
        }
    }
}
