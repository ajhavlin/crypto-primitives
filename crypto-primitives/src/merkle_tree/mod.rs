#![allow(clippy::needless_range_loop)]

use core::convert::TryFrom;

/// Defines a trait to chain two types of CRHs.
use crate::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    sponge::Absorb,
    Error,
};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
};
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;
use ark_std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    hash::{BuildHasherDefault, Hash},
};
use hashbrown::HashMap;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[cfg(feature = "constraints")]
pub mod constraints;

#[cfg(test)]
mod tests;

#[cfg(all(
    target_has_atomic = "8",
    target_has_atomic = "16",
    target_has_atomic = "32",
    target_has_atomic = "64",
    target_has_atomic = "ptr"
))]
pub(super) type DefaultHasher = ahash::AHasher;

#[cfg(not(all(
    target_has_atomic = "8",
    target_has_atomic = "16",
    target_has_atomic = "32",
    target_has_atomic = "64",
    target_has_atomic = "ptr"
)))]
pub(super) type DefaultHasher = fnv::FnvHasher;

pub mod implicit;

type PackedInnerCopath<P> = (usize, usize, Vec<u8>, Vec<<P as Config>::InnerDigest>);

/// Convert the hash digest in different layers by converting previous layer's output to
/// `TargetType`, which is a `Borrow` to next layer's input.
pub trait DigestConverter<From, To: ?Sized> {
    type TargetType: Borrow<To>;
    fn convert(item: From) -> Result<Self::TargetType, Error>;
}

/// A trivial converter where digest of previous layer's hash is the same as next layer's input.
pub struct IdentityDigestConverter<T> {
    _prev_layer_digest: T,
}

impl<T> DigestConverter<T, T> for IdentityDigestConverter<T> {
    type TargetType = T;
    fn convert(item: T) -> Result<T, Error> {
        Ok(item)
    }
}

/// Convert previous layer's digest to bytes and use bytes as input for next layer's digest.
/// TODO: `ToBytes` trait will be deprecated in future versions.
pub struct ByteDigestConverter<T: CanonicalSerialize> {
    _prev_layer_digest: T,
}

impl<T: CanonicalSerialize> DigestConverter<T, [u8]> for ByteDigestConverter<T> {
    type TargetType = Vec<u8>;

    fn convert(item: T) -> Result<Self::TargetType, Error> {
        // TODO: In some tests, `serialize` is not consistent with constraints. Try fix those.
        Ok(crate::to_uncompressed_bytes!(item)?)
    }
}

/// Merkle tree has two types of hashes.
/// * `LeafHash`: Convert leaf to leaf digest
/// * `TwoToOneHash`: Compress two inner digests to one inner digest
pub trait Config {
    type Leaf: ?Sized + Send; // merkle tree does not store the leaf
                              // leaf layer
    type LeafDigest: Clone
        + Eq
        + Debug
        + Hash
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize
        + Send
        + Sync;

    // transition between leaf layer to inner layer
    type LeafInnerDigestConverter: DigestConverter<
        Self::LeafDigest,
        <Self::TwoToOneHash as TwoToOneCRHScheme>::Input,
    >;
    // inner layer
    type InnerDigest: Clone
        + Eq
        + Debug
        + Hash
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize
        + Send
        + Sync
        + Absorb;

    // Tom's Note: in the future, if we want different hash function, we can simply add more
    // types of digest here and specify a digest converter. Same for constraints.

    /// leaf -> leaf digest
    /// If leaf hash digest and inner hash digest are different, we can create a new
    /// leaf hash which wraps the original leaf hash and convert its output to `Digest`.
    type LeafHash: CRHScheme<Input = Self::Leaf, Output = Self::LeafDigest>;
    /// 2 inner digest -> inner digest
    type TwoToOneHash: TwoToOneCRHScheme<Output = Self::InnerDigest>;
}

pub type TwoToOneParam<P> = <<P as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters;
pub type LeafParam<P> = <<P as Config>::LeafHash as CRHScheme>::Parameters;

/// Stores the hashes of a particular path (in order) from root to leaf.
/// For example:
/// ```tree_diagram
///         [A]
///        /   \
///      [B]    C
///     / \   /  \
///    D [E] F    H
///   .. / \ ....
///    [I] J
/// ```
///  Suppose we want to prove I, then `leaf_sibling_hash` is J, `auth_path` is `[C,D]`
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    PartialEq(bound = "P: Config"),
    Clone(bound = "P: Config"),
    Debug(bound = "P: Config"),
    Default(bound = "P: Config")
)]
pub struct Path<P: Config> {
    pub leaf_sibling_hash: P::LeafDigest,
    /// The sibling of path node ordered from higher layer to lower layer (does not include root node).
    pub auth_path: Vec<P::InnerDigest>,
    /// stores the leaf index of the node
    pub leaf_index: usize,
}

impl<P: Config> Path<P> {
    /// The position of on_path node in `leaf_and_sibling_hash` and `non_leaf_and_sibling_hash_path`.
    /// `position[i]` is 0 (false) iff `i`th on-path node from top to bottom is on the left.
    ///
    /// This function simply converts `self.leaf_index` to boolean array in big endian form.
    #[allow(unused)] // this function is actually used when r1cs feature is on
    fn position_list(&'_ self) -> impl '_ + Iterator<Item = bool> {
        (0..self.auth_path.len() + 1)
            .map(move |i| ((self.leaf_index >> i) & 1) != 0)
            .rev()
    }
}

impl<P: Config> Path<P> {
    /// Verify that a leaf is at `self.index` of the merkle tree.
    /// * `leaf_size`: leaf size in number of bytes
    ///
    /// `verify` infers the tree height by setting `tree_height = self.auth_path.len() + 2`
    pub fn verify<L: Borrow<P::Leaf>>(
        &self,
        leaf_hash_params: &LeafParam<P>,
        two_to_one_params: &TwoToOneParam<P>,
        root_hash: &P::InnerDigest,
        leaf: L,
    ) -> Result<bool, crate::Error> {
        // calculate leaf hash
        let claimed_leaf_hash = P::LeafHash::evaluate(&leaf_hash_params, leaf)?;
        // check hash along the path from bottom to root
        let (left_child, right_child) =
            select_left_right_child(self.leaf_index, &claimed_leaf_hash, &self.leaf_sibling_hash)?;

        // leaf layer to inner layer conversion
        let left_child = P::LeafInnerDigestConverter::convert(left_child)?;
        let right_child = P::LeafInnerDigestConverter::convert(right_child)?;

        let mut curr_path_node =
            P::TwoToOneHash::evaluate(&two_to_one_params, left_child, right_child)?;

        // we will use `index` variable to track the position of path
        let mut index = self.leaf_index;
        index >>= 1;

        // Check levels between leaf level and root
        for level in (0..self.auth_path.len()).rev() {
            // check if path node at this level is left or right
            let (left, right) =
                select_left_right_child(index, &curr_path_node, &self.auth_path[level])?;
            // update curr_path_node
            curr_path_node = P::TwoToOneHash::compress(&two_to_one_params, &left, &right)?;
            index >>= 1;
        }

        // check if final hash is root
        if &curr_path_node != root_hash {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Optimized data structure to store multiple nodes proofs.
/// For example:
/// ```tree_diagram
///         [A]             d = 0
///        /   \
///      [B]    C           d = 1
///     / \    /  \
///    D [E]  F    H        d = 2
///  ... / \ / \ ....
///    [I] J L  M           d = 3
/// ```
///  Suppose we want to prove I and J, then:
///     `tree_height`: `4`
///     `leaf_copath`: `[]`
///     `inner_copath`: `[(2,0,D), (1,1,C)]` (store packed as `(2,0,[1,+1],[D,C])`)
///     `leaf_indexes` is: `[2,3]` (indexes in Merkle Tree leaves vector)
///
///  We can reconstruct upfront the minimal copath needed for the proof:
///  First, we reconstruct the minimal copath at the leaf layer (`depth = tree_height-1`).
///  This is only those sibling leaf digests that are required to complete parents of on-path leaves but are not themselves on-path.
///  The leaf copath is thus `[J,I]/[I,J]=[]`.
///  We then repeat this for each inner layer, computing only the non-on-path siblings needed to complete parents of the union of all single paths.
///  The inner copath digests are stored as (depth, index, digest) tuples ordered by (depth, index).
///  Thus, inner copath is `[(2,0,D), (1,1,C)]`.
///  Intuitively, CoSet transmits only what's missing to recompute every parent on the shared union-of-paths.

#[derive(Derivative, CanonicalSerialize)]
#[derivative(
    Clone(bound = "P: Config"),
    Debug(bound = "P: Config"),
    Default(bound = "P: Config")
)]
pub struct CoPath<P: Config> {
    /// stores the height of the tree (>= 2) to drive CoSet decoding
    pub(crate) tree_height: usize,
    /// For leaf layer, stores co-path digests (B*_{d-1}) in ascending sibling index order
    pub leaf_copath: Vec<P::LeafDigest>,
    /// For inner layers, stores co-path entries packed as (start_depth, start_index, packed deltas, digests)
    pub inner_copath: Option<PackedInnerCopath<P>>,
    /// stores the leaf indexes of the nodes to prove
    pub leaf_indexes: Vec<usize>,
}

/// Supertrait for CanonicalDeserialize:
impl<P: Config> Valid for CoPath<P> {
    fn check(&self) -> Result<(), SerializationError> {
        if self.tree_height < 2 {
            return Err(SerializationError::InvalidData);
        }
        // Propagate field checks to ensure the whole structure is valid.
        self.leaf_copath.check()?;
        self.inner_copath.check()?;
        self.leaf_indexes.check()
    }
}

impl<P: Config> CanonicalDeserialize for CoPath<P> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let tree_height = usize::deserialize_with_mode(&mut reader, compress, validate)?;
        let leaf_copath =
            Vec::<P::LeafDigest>::deserialize_with_mode(&mut reader, compress, validate)?;
        let inner_copath =
            Option::<PackedInnerCopath<P>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let leaf_indexes = Vec::<usize>::deserialize_with_mode(&mut reader, compress, validate)?;
        if tree_height < 2 {
            return Err(SerializationError::InvalidData);
        }
        Ok(CoPath {
            tree_height,
            leaf_copath,
            inner_copath,
            leaf_indexes,
        })
    }
}

impl<P: Config> CoPath<P> {
    /// Verify that leaves are at `self.leaf_indexes` of the merkle tree.
    /// Note that the order of the leaves hashes should match the leaves respective indexes
    /// * `leaf_size`: leaf size in number of bytes
    ///
    /// `expected_tree_height` must equal the height of the tree the proof was generated from;
    /// the verifier supplies this value — it is not taken from the (prover-controlled) proof.
    pub fn verify<L: Borrow<P::Leaf> + Clone>(
        &self,
        leaf_hash_params: &LeafParam<P>,
        two_to_one_params: &TwoToOneParam<P>,
        root_hash: &P::InnerDigest,
        expected_tree_height: usize,
        leaves: impl IntoIterator<Item = L>,
    ) -> Result<bool, crate::Error> {
        if self.leaf_indexes.is_empty() {
            return Err(crate::Error::GenericError(ark_std::boxed::Box::new(
                ark_std::io::Error::new(
                    ark_std::io::ErrorKind::InvalidInput,
                    "batch proof must contain at least one leaf index",
                ),
            )));
        }

        if self.tree_height < 2 {
            return Err(crate::Error::GenericError(ark_std::boxed::Box::new(
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

        // hash opened leaves and build map containing all leaf digests needed at bottom layer
        let mut leaves_iter = leaves.into_iter();
        let mut leaf_level =
            Self::ingest_leaves(&self.leaf_indexes, &mut leaves_iter, leaf_hash_params)?;

        // Compute on-path sets A_j and reconstruct expected B*_j = siblings(A_j) \ A_j
        let index_set: BTreeSet<usize> = self.leaf_indexes.iter().copied().collect();
        let on_path = compute_on_path(leaf_depth, &index_set); // holds indices of on-path nodes at depth d

        // compute minimal copath at leaf layer (B*_{d-1})
        let expected_leaf_coset = Self::expected_leaf_coset(leaf_depth, &on_path);
        if !Self::validate_leaf_copath(&expected_leaf_coset, &self.leaf_copath, &mut leaf_level) {
            return Ok(false);
        }

        // prepare inner-level maps for non-on-path siblings and computed parents
        let mut inner_levels: Vec<BTreeMap<usize, P::InnerDigest>> =
            (0..d).map(|_| BTreeMap::new()).collect();

        // LookUp table to speedup computation avoid redundant hash computations
        let mut hash_lut: HashMap<usize, P::InnerDigest, _> =
            HashMap::with_hasher(BuildHasherDefault::<DefaultHasher>::default());

        // Decode received inner copath and add digests to LUT
        if !Self::decode_inner_copath(d, &self.inner_copath, &mut inner_levels, &mut hash_lut) {
            return Ok(false);
        }

        if !Self::recompute_bottom_parents(
            leaf_depth,
            &on_path,
            &leaf_level,
            two_to_one_params,
            &mut hash_lut,
            &mut inner_levels,
        )? {
            return Ok(false);
        }

        if !Self::recompute_inner_layers(
            leaf_depth,
            &on_path,
            two_to_one_params,
            &mut hash_lut,
            &mut inner_levels,
        )? {
            return Ok(false);
        }

        // check root
        match inner_levels[0].get(&0) {
            Some(h) => Ok(h == root_hash), // valid: Ok(true)
            None => Ok(false),
        }
    }

    /// Encodes the inner co-path entries [(depth, index, digest), ...] as compact delta encodings.
    /// Keeps the first (depth, index) entry, then zigzag encodes signed deltas of subsequent paris,
    /// collecting the corresponding digests in order.
    /// Result is a tuple (start_depth: usize, start_index: usize, deltas: Vec<u8>, digests: Vec<<P as Config>::InnerDigest>)
    ///
    /// For example:
    /// ```tree_diagram
    ///                         [A]                           d = 0
    ///                    /           \
    ///                  [B]           [C]                    d = 1
    ///                /    \         /    \
    ///              [D]     E       F     [G]                d = 2
    ///              / \    / \     / \    / \
    ///            H   I  [J]  K   L  [M]  N   O              d = 3
    ///           / \ / \ / \ / \ / \ / \ / \ / \
    ///              .... 4 5 6 7 8 9 10 11 ....              d = 4
    /// ```
    ///
    ///  Suppose we want to prove the following openings:
    /// ```text
    ///  I = {6, 8}
    /// ```
    ///  With the CoSet strategy:
    ///  * we take the union of all single paths and compute
    ///    `B*_j = siblings(A_j) \ A_j` for each depth `j`,
    ///  * at the leaf layer we compute `B*_{4} = {(4, 7), (4, 9)}`,
    ///  * and across inner layers (depths `1..3`) we compute:
    ///    `B*_{1} = {(1, 0), (1, 1)}`, `B*_{2} = {(2, 0), (2, 3)}`, `B*_{3} = {(3, 2), (3, 5)}`,
    ///  So the CoPath carries:
    ///  * `2` leaf-layer digests (`leaf_copath`),
    ///  * `6` inner-layer digests (`inner_copath`),
    ///
    ///  We keep `leaf_copath` as-is but instead of storing all 6 `(depth, index)` pairs explicitly, we store:
    ///
    ///  * a starting coordinate:
    /// ```text
    ///  start_depth = 1
    ///  start_index = 0
    /// ```
    ///
    ///  * followed by signed deltas between consecutive coordinates:
    /// ```text
    ///  (Δd, Δi) sequence:
    ///    (0, +1),
    ///    (+1, -1),
    ///    (0, +3),
    ///    (+1, -1),
    ///    (0, +3)
    /// ```
    ///
    ///  Each `(Δd, Δi)` is encoded to unsigned and then varint-encoded. All of these
    ///  deltas are very small (−1, 0, +1, +3), so each encoded value fits in a
    ///  single byte. On a 64-bit platform:
    ///
    ///  * naive coordinate encoding for 6 entries as `(depth: usize, index: usize)`
    ///    uses roughly `6 × 2 × 8 = 96` bytes,
    ///  * the packed representation uses:
    ///    * one `(start_depth, start_index)` pair (16 bytes),
    ///    * plus `5 × 2` varints (10 bytes/20 bytes for index in a large tree),
    ///    * for ~ 26/36 bytes of coordinate data.
    fn pack_inner_copath(
        entries: &[(usize, usize, P::InnerDigest)],
    ) -> Option<PackedInnerCopath<P>> {
        if entries.is_empty() {
            return None;
        }

        let first = &entries[0];
        let mut deltas = Vec::new();
        let mut digests = Vec::with_capacity(entries.len());
        let mut prev_depth = i64::try_from(first.0).ok()?;
        let mut prev_index = i64::try_from(first.1).ok()?;
        digests.push(first.2.clone());

        for &(depth, index, ref digest) in entries.iter().skip(1) {
            let depth_i64 = i64::try_from(depth).ok()?;
            let index_i64 = i64::try_from(index).ok()?;
            encode_delta(&mut deltas, depth_i64 - prev_depth);
            encode_delta(&mut deltas, index_i64 - prev_index);
            digests.push(digest.clone());
            prev_depth = depth_i64;
            prev_index = index_i64;
        }

        Some((first.0, first.1, deltas, digests))
    }

    /// Hashes provided leaves (ordered by `leaf_indexes`) and returns a map from leaf index to digest.
    pub(super) fn ingest_leaves<L, I>(
        leaf_indexes: &[usize],
        leaves: &mut I,
        leaf_hash_params: &LeafParam<P>,
    ) -> Result<BTreeMap<usize, P::LeafDigest>, crate::Error>
    where
        L: Borrow<P::Leaf>,
        I: Iterator<Item = L>,
    {
        let mut leaf_level: BTreeMap<usize, P::LeafDigest> = BTreeMap::new();
        for &idx in leaf_indexes {
            let leaf = leaves
                .next()
                .ok_or_else(|| crate::Error::IncorrectInputLength(leaf_indexes.len()))?;
            let leaf_hash = P::LeafHash::evaluate(leaf_hash_params, leaf.borrow())?;
            leaf_level.insert(idx, leaf_hash);
        }
        if leaves.next().is_some() {
            return Err(crate::Error::IncorrectInputLength(leaf_indexes.len()));
        }
        Ok(leaf_level)
    }

    /// Computes the minimal leaf-layer copath indices `B*_{d-1}` (siblings of on-path nodes not on-path).
    pub(super) fn expected_leaf_coset(leaf_depth: usize, on_path: &[Vec<usize>]) -> Vec<usize> {
        let mut expected_leaf_coset: Vec<usize> = Vec::new();
        for &path_idx in on_path[leaf_depth].iter() {
            let sibling_idx = path_idx ^ 1;
            if on_path[leaf_depth].binary_search(&sibling_idx).is_err() {
                expected_leaf_coset.push(sibling_idx); // copath element needed for proof
            }
        }
        expected_leaf_coset.sort_unstable(); // canonical order
        expected_leaf_coset
    }

    /// Confirms provided leaf copath matches the expected indices and augments `leaf_level` with them.
    pub(super) fn validate_leaf_copath(
        expected_leaf_coset: &[usize],
        provided_leaf_copath: &[P::LeafDigest],
        leaf_level: &mut BTreeMap<usize, P::LeafDigest>,
    ) -> bool {
        if expected_leaf_coset.len() != provided_leaf_copath.len() {
            return false;
        }

        for (sibling_idx, sibling_digest) in expected_leaf_coset.iter().zip(provided_leaf_copath) {
            match leaf_level.get(sibling_idx) {
                Some(existing) if existing != sibling_digest => return false, // digest must match new one
                _ => {
                    leaf_level.insert(*sibling_idx, sibling_digest.clone());
                }
            }
        }
        true
    }

    /// Recomputes parents at depth `d-2` (immediately above leaves) using the leaf digests and LUT.
    pub(super) fn recompute_bottom_parents(
        leaf_depth: usize,
        on_path: &[Vec<usize>],
        leaf_level: &BTreeMap<usize, P::LeafDigest>,
        two_to_one_params: &TwoToOneParam<P>,
        hash_lut: &mut HashMap<usize, P::InnerDigest, BuildHasherDefault<DefaultHasher>>,
        inner_levels: &mut [BTreeMap<usize, P::InnerDigest>],
    ) -> Result<bool, crate::Error> {
        for &parent_index in on_path[leaf_depth - 1].iter() {
            let left = leaf_level.get(&(parent_index * 2)).cloned();
            let right = leaf_level.get(&(parent_index * 2 + 1)).cloned();
            let (left, right) = match (left, right) {
                (Some(left), Some(right)) => (left, right),
                _ => return Ok(false),
            };
            let parent = P::TwoToOneHash::evaluate(
                two_to_one_params,
                P::LeafInnerDigestConverter::convert(left)?, // convert to inner-hash input type
                P::LeafInnerDigestConverter::convert(right)?,
            )?;
            inner_levels[leaf_depth - 1].insert(parent_index, parent.clone());
            // add parent to LUT at heap index
            let heap_idx = level_index(leaf_depth - 1, parent_index);
            hash_lut.insert(heap_idx, parent);
        }
        Ok(true)
    }

    /// Recomputes inner layers up to the root using cached inner digests and stores results in LUT.
    pub(super) fn recompute_inner_layers(
        leaf_depth: usize,
        on_path: &[Vec<usize>],
        two_to_one_params: &TwoToOneParam<P>,
        hash_lut: &mut HashMap<usize, P::InnerDigest, BuildHasherDefault<DefaultHasher>>,
        inner_levels: &mut [BTreeMap<usize, P::InnerDigest>],
    ) -> Result<bool, crate::Error> {
        for depth in (1..=leaf_depth - 1).rev() {
            let parent_depth = depth - 1;
            for &parent_index in on_path[parent_depth].iter() {
                let left = inner_levels[depth].get(&(parent_index * 2)).cloned();
                let right = inner_levels[depth].get(&(parent_index * 2 + 1)).cloned();
                let (left, right) = match (left, right) {
                    (Some(left), Some(right)) => (left, right),
                    _ => return Ok(false),
                };
                let parent = P::TwoToOneHash::compress(two_to_one_params, &left, &right)?;
                inner_levels[parent_depth].insert(parent_index, parent.clone());
                // add parent to LUT at heap index
                let heap_idx = level_index(parent_depth, parent_index);
                hash_lut.insert(heap_idx, parent);
            }
        }
        Ok(true)
    }

    /// Decodes inner co-path entries back into their usize equivalents
    /// Inserts corresponding digest into the LUT for memoisation.
    fn decode_inner_copath(
        tree_height: usize,
        inner_copath: &Option<PackedInnerCopath<P>>,
        inner_levels: &mut [BTreeMap<usize, P::InnerDigest>],
        hash_lut: &mut HashMap<usize, P::InnerDigest, BuildHasherDefault<DefaultHasher>>,
    ) -> bool {
        if let Some((start_depth, start_index, deltas, digests)) = inner_copath {
            // verifier rejects if remaining deltas with empty digests
            if digests.is_empty() {
                return deltas.is_empty();
            }

            // init (depth, index) accumulation as i64
            let mut depth = match i64::try_from(*start_depth) {
                Ok(value) => value,
                Err(_) => return false,
            };
            let mut index = match i64::try_from(*start_index) {
                Ok(value) => value,
                Err(_) => return false,
            };
            let mut cursor = 0usize;
            let mut prev_coord: Option<(usize, usize)> = None;

            // Helper to insert digest into the LUT
            let mut push_entry =
                |depth_i64: i64, index_i64: i64, digest: &P::InnerDigest| -> bool {
                    let depth_usize = match usize::try_from(depth_i64) {
                        Ok(v) => v,
                        Err(_) => return false,
                    };
                    let index_usize = match usize::try_from(index_i64) {
                        Ok(v) => v,
                        Err(_) => return false,
                    };
                    if depth_usize == 0 || depth_usize >= tree_height {
                        return false;
                    }
                    // ensure provers ordering is consistent
                    if let Some((pd, pi)) = prev_coord {
                        if (depth_usize, index_usize) < (pd, pi) {
                            return false;
                        }
                    }
                    // check for conflicting siblings at the same coordinate
                    if let Some(existing) = inner_levels[depth_usize].get(&index_usize) {
                        if existing != digest {
                            return false;
                        }
                    } else {
                        inner_levels[depth_usize].insert(index_usize, digest.clone());
                    }
                    // seed LUT with known siblings
                    let heap_idx = level_index(depth_usize, index_usize);
                    hash_lut.entry(heap_idx).or_insert_with(|| digest.clone());
                    prev_coord = Some((depth_usize, index_usize));
                    true
                };

            if !push_entry(depth, index, &digests[0]) {
                return false;
            }

            // accumulate remaining digests
            for digest in digests.iter().skip(1) {
                let depth_delta = match decode_delta(deltas, &mut cursor) {
                    Some(delta) => delta,
                    None => return false,
                };
                let index_delta = match decode_delta(deltas, &mut cursor) {
                    Some(delta) => delta,
                    None => return false,
                };
                // next (depth, index)
                depth = match depth.checked_add(depth_delta) {
                    Some(value) => value,
                    None => return false,
                };
                index = match index.checked_add(index_delta) {
                    Some(value) => value,
                    None => return false,
                };
                // attempt push
                if !push_entry(depth, index, digest) {
                    return false;
                }
            }

            if cursor != deltas.len() {
                return false;
            }
        }

        true
    }

    // The position of on_path node in `leaf_and_sibling_hash` and `non_leaf_and_sibling_hash_path`.
    // `position[i]` is 0 (false) iff `i`th on-path node from top to bottom is on the left.
    //
    // This function simply converts every index in `self.leaf_indexes` to boolean array in big endian form.
    #[allow(unused)] // this function is actually used when r1cs feature is on
    fn position_list(&'_ self) -> impl '_ + Iterator<Item = Vec<bool>> {
        let path_len = self.tree_height.saturating_sub(2);

        cfg_into_iter!(self.leaf_indexes.clone())
            .map(move |i| {
                (0..path_len + 1)
                    .map(move |j| ((i >> j) & 1) != 0)
                    .rev()
                    .collect()
            })
            .collect::<Vec<_>>()
            .into_iter()
    }
}

/// `index` is the first `path.len()` bits of
/// the position of tree.
///
/// If the least significant bit of `index` is 0, then `sibling` will be left and `computed` will be right.
/// Otherwise, `sibling` will be right and `computed` will be left.
///
/// Returns: (left, right)
fn select_left_right_child<L: Clone>(
    index: usize,
    computed_hash: &L,
    sibling_hash: &L,
) -> Result<(L, L), crate::Error> {
    let is_left = index & 1 == 0;
    let mut left_child = computed_hash;
    let mut right_child = sibling_hash;
    if !is_left {
        core::mem::swap(&mut left_child, &mut right_child);
    }
    Ok((left_child.clone(), right_child.clone()))
}

/// Defines a merkle tree data structure.
/// This merkle tree has runtime fixed height, and assumes number of leaves is 2^height.
///
/// TODO: add RFC-6962 compatible merkle tree in the future.
/// For this release, padding will not be supported because of security concerns: if the leaf hash and two to one hash uses same underlying
/// CRH, a malicious prover can prove a leaf while the actual node is an inner node. In the future, we can prefix leaf hashes in different layers to
/// solve the problem.
#[derive(Derivative)]
#[derivative(Clone(bound = "P: Config"))]
pub struct MerkleTree<P: Config> {
    /// stores the non-leaf nodes in level order. The first element is the root node.
    /// The ith nodes (starting at 1st) children are at indices `2*i`, `2*i+1`
    non_leaf_nodes: Vec<P::InnerDigest>,
    /// store the hash of leaf nodes from left to right
    leaf_nodes: Vec<P::LeafDigest>,
    /// Store the inner hash parameters
    two_to_one_hash_param: TwoToOneParam<P>,
    /// Store the leaf hash parameters
    leaf_hash_param: LeafParam<P>,
    /// Stores the height of the MerkleTree
    height: usize,
}

impl<P: Config> MerkleTree<P> {
    /// Create an empty merkle tree such that all leaves are zero-filled.
    /// Consider using a sparse merkle tree if you need the tree to be low memory
    pub fn blank(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        height: usize,
    ) -> Result<Self, crate::Error> {
        // use empty leaf digest
        let leaf_digests = vec![P::LeafDigest::default(); 1 << (height - 1)];
        Self::new_with_leaf_digest(leaf_hash_param, two_to_one_hash_param, leaf_digests)
    }

    /// Returns a new merkle tree. `leaves.len()` should be power of two.
    pub fn new<L: AsRef<P::Leaf> + Send>(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        #[cfg(not(feature = "parallel"))] leaves: impl IntoIterator<Item = L>,
        #[cfg(feature = "parallel")] leaves: impl IntoParallelIterator<Item = L>,
    ) -> Result<Self, crate::Error> {
        let leaf_digests: Vec<_> = cfg_into_iter!(leaves)
            .map(|input| P::LeafHash::evaluate(leaf_hash_param, input.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;

        Self::new_with_leaf_digest(leaf_hash_param, two_to_one_hash_param, leaf_digests)
    }

    pub fn new_with_leaf_digest(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        leaf_digests: Vec<P::LeafDigest>,
    ) -> Result<Self, crate::Error> {
        let leaf_nodes_size = leaf_digests.len();
        assert!(
            leaf_nodes_size.is_power_of_two() && leaf_nodes_size > 1,
            "`leaves.len() should be power of two and greater than one"
        );
        let non_leaf_nodes_size = leaf_nodes_size - 1;

        let tree_height = tree_height(leaf_nodes_size);

        let hash_of_empty: P::InnerDigest = P::InnerDigest::default();

        // initialize the merkle tree as array of nodes in level order
        let mut non_leaf_nodes: Vec<P::InnerDigest> = cfg_into_iter!(0..non_leaf_nodes_size)
            .map(|_| hash_of_empty.clone())
            .collect();

        // Compute the starting indices for each non-leaf level of the tree
        let mut index = 0;
        let mut level_indices = Vec::with_capacity(tree_height - 1);
        for _ in 0..(tree_height - 1) {
            level_indices.push(index);
            index = left_child(index);
        }

        // compute the hash values for the non-leaf bottom layer
        {
            let start_index = level_indices.pop().unwrap();
            let upper_bound = left_child(start_index);

            cfg_iter_mut!(non_leaf_nodes[start_index..upper_bound])
                .enumerate()
                .try_for_each(|(i, n)| {
                    // `left_child(current_index)` and `right_child(current_index) returns the position of
                    // leaf in the whole tree (represented as a list in level order). We need to shift it
                    // by `-upper_bound` to get the index in `leaf_nodes` list.

                    // similarly, we need to rescale i by start_index
                    // to get the index outside the slice and in the level-ordered list of nodes

                    let current_index = i + start_index;
                    let left_leaf_index = left_child(current_index) - upper_bound;
                    let right_leaf_index = right_child(current_index) - upper_bound;

                    *n = P::TwoToOneHash::evaluate(
                        two_to_one_hash_param,
                        P::LeafInnerDigestConverter::convert(
                            leaf_digests[left_leaf_index].clone(),
                        )?,
                        P::LeafInnerDigestConverter::convert(
                            leaf_digests[right_leaf_index].clone(),
                        )?,
                    )?;
                    Ok::<(), crate::Error>(())
                })?;
        }

        // compute the hash values for nodes in every other layer in the tree
        level_indices.reverse();
        for &start_index in &level_indices {
            // The layer beginning `start_index` ends at `upper_bound` (exclusive).
            let upper_bound = left_child(start_index);

            let (nodes_at_level, nodes_at_prev_level) =
                non_leaf_nodes[..].split_at_mut(upper_bound);
            // Iterate over the nodes at the current level, and compute the hash of each node
            cfg_iter_mut!(nodes_at_level[start_index..])
                .enumerate()
                .try_for_each(|(i, n)| {
                    // `left_child(current_index)` and `right_child(current_index) returns the position of
                    // leaf in the whole tree (represented as a list in level order). We need to shift it
                    // by `-upper_bound` to get the index in `leaf_nodes` list.

                    // similarly, we need to rescale i by start_index
                    // to get the index outside the slice and in the level-ordered list of nodes
                    let current_index = i + start_index;
                    let left_leaf_index = left_child(current_index) - upper_bound;
                    let right_leaf_index = right_child(current_index) - upper_bound;

                    // need for unwrap as Box<Error> does not implement trait Send
                    *n = P::TwoToOneHash::compress(
                        two_to_one_hash_param,
                        nodes_at_prev_level[left_leaf_index].clone(),
                        nodes_at_prev_level[right_leaf_index].clone(),
                    )?;
                    Ok::<_, crate::Error>(())
                })?;
        }
        Ok(MerkleTree {
            leaf_nodes: leaf_digests,
            non_leaf_nodes,
            height: tree_height,
            leaf_hash_param: leaf_hash_param.clone(),
            two_to_one_hash_param: two_to_one_hash_param.clone(),
        })
    }

    /// Returns the root of the Merkle tree.
    pub fn root(&self) -> P::InnerDigest {
        self.non_leaf_nodes[0].clone()
    }

    /// Returns the height of the Merkle tree.
    pub fn height(&self) -> usize {
        self.height
    }

    /// Given the `index` of a leaf, returns the digest of its leaf sibling
    pub fn get_leaf_sibling_hash(&self, index: usize) -> P::LeafDigest {
        if index & 1 == 0 {
            // leaf is left child
            self.leaf_nodes[index + 1].clone()
        } else {
            // leaf is right child
            self.leaf_nodes[index - 1].clone()
        }
    }

    /// Returns the authentication path from leaf at `index` to root, as a Vec of digests
    fn compute_auth_path(&self, index: usize) -> Vec<P::InnerDigest> {
        // gather basic tree information
        let tree_height = tree_height(self.leaf_nodes.len());

        // Get Leaf hash, and leaf sibling hash,
        let leaf_index_in_tree = convert_index_to_last_level(index, tree_height);

        // path.len() = `tree height - 2`, the two missing elements being the leaf sibling hash and the root
        let mut path = Vec::with_capacity(tree_height - 2);
        // Iterate from the bottom layer after the leaves, to the top, storing all sibling node's hash values.
        let mut current_node = parent(leaf_index_in_tree).unwrap();
        while !is_root(current_node) {
            let sibling_node = sibling(current_node).unwrap();
            path.push(self.non_leaf_nodes[sibling_node].clone());
            current_node = parent(current_node).unwrap();
        }

        debug_assert_eq!(path.len(), tree_height - 2);

        // we want to make path from root to bottom
        path.reverse();
        path
    }

    /// Returns the authentication path from leaf at `index` to root.
    pub fn generate_proof(&self, index: usize) -> Result<Path<P>, crate::Error> {
        let path = self.compute_auth_path(index);
        Ok(Path {
            leaf_index: index,
            auth_path: path,
            leaf_sibling_hash: self.get_leaf_sibling_hash(index),
        })
    }

    /// Returns a CoPath struct (a compressed membership proof for a set of leaves),
    /// sufficient to verify each leaf up to the root.
    /// Indexes are internally sorted and emitted in this order.
    ///
    /// With the CoSet (minimal co-path) encoding, we do not store full per-leaf authentication paths.
    /// Instead we collect, for each tree level, only those siblings of on-path nodes that are not themselves on-path.
    /// This yields a smaller proof than front-incremental prefix encoding in the typical case,
    /// while preserving the same verification interface.
    ///
    /// For sorted indexes, the CoSet proof carries:
    /// * `tree_height`;
    /// * `leaf_indexes` (ascending, unique);
    /// * `leaf_copath`: the leaf-layer co-path digests `B*_{d-1}`, in ascending sibling index order;
    /// * `inner_copath`: the inner co-path packed as `(start_depth, start_index, packed deltas, digests)`.
    ///
    /// When verifying the proof, leaves hashes should be supplied in order of `leaf_indexes`, that is:
    /// ```text
    /// let ordered_leaves: Vec<_> = proof.leaf_indexes.iter().map(|&i| leaves[i].clone()).collect();
    /// ```
    /// Notes:
    /// * Empty input (`indexes` is empty) returns a structurally valid empty proof carrying `tree_height`,
    ///   and verification succeeds vacuously against the claimed root.
    pub fn generate_multi_proof(
        &self,
        indexes: impl IntoIterator<Item = usize>,
    ) -> Result<CoPath<P>, crate::Error> {
        // pruned and sorted for encoding efficiency
        let indexes: BTreeSet<usize> = indexes.into_iter().collect();
        let d = self.height();

        // TODO: should empty query return structurally valid empty proof
        if indexes.is_empty() {
            return Ok(CoPath {
                tree_height: d,
                leaf_copath: Vec::new(),
                inner_copath: None,
                leaf_indexes: Vec::new(),
            });
        }

        let leaf_depth = d - 1;
        // Compute on-path sets A_j and then minimal co-path B*_j = siblings(A_j) \ A_j
        let on_path = compute_on_path(leaf_depth, &indexes);

        // leaf layer (depth = d-1)
        let mut leaf_coset_ids: Vec<usize> = Vec::new();
        for &path_idx in on_path[leaf_depth].iter() {
            let sibling_idx = path_idx ^ 1;
            if on_path[leaf_depth].binary_search(&sibling_idx).is_err() {
                leaf_coset_ids.push(sibling_idx);
            }
        }
        leaf_coset_ids.sort_unstable();

        let mut leaf_copath = Vec::with_capacity(leaf_coset_ids.len());
        for sibling_idx in leaf_coset_ids.iter().copied() {
            let sibling_digest = self
                .leaf_nodes
                .get(sibling_idx)
                .ok_or_else(|| crate::Error::IncorrectInputLength(self.leaf_nodes.len()))?;
            leaf_copath.push(sibling_digest.clone());
        }

        // inner layers (depth 1..d-2)
        let mut inner_copath_entries: Vec<(usize, usize, P::InnerDigest)> = Vec::new();
        for depth in 1..leaf_depth {
            for &path_idx in on_path[depth].iter() {
                let sibling_idx = path_idx ^ 1;
                if on_path[depth].binary_search(&sibling_idx).is_err() {
                    let heap_idx = level_index(depth, sibling_idx);
                    let sibling_digest = self.non_leaf_nodes.get(heap_idx).ok_or_else(|| {
                        crate::Error::IncorrectInputLength(self.non_leaf_nodes.len())
                    })?;
                    inner_copath_entries.push((depth, sibling_idx, sibling_digest.clone()));
                }
            }
        }
        // canonicalise order
        inner_copath_entries.sort_by_key(|(dpt, idx, _)| (*dpt, *idx));
        let inner_copath = CoPath::<P>::pack_inner_copath(&inner_copath_entries);

        Ok(CoPath {
            tree_height: d,
            leaf_copath,
            inner_copath,
            leaf_indexes: Vec::from_iter(indexes),
        })
    }

    /// Returns an [`ImplicitCoPath`] for the given leaf indexes.
    ///
    /// This is a coordinate-free variant of [`Self::generate_multi_proof`]: both prover and
    /// verifier independently derive the positions of required copath nodes from `leaf_indexes`
    /// and `tree_height`, so only the digests are transmitted (in canonical depth-then-index
    /// order). The proof is strictly smaller than a `CoPath` for any tree with more than one
    /// inner layer, since no coordinate metadata is included.
    pub fn generate_implicit_multi_proof(
        &self,
        indexes: impl IntoIterator<Item = usize>,
    ) -> Result<implicit::ImplicitCoPath<P>, crate::Error> {
        use ark_std::collections::BTreeSet;
        let indexes: BTreeSet<usize> = indexes.into_iter().collect();
        let d = self.height();

        if indexes.is_empty() {
            return Ok(implicit::ImplicitCoPath {
                tree_height: d,
                leaf_copath: Vec::new(),
                inner_copath: Vec::new(),
                leaf_indexes: Vec::new(),
            });
        }

        let leaf_depth = d - 1;
        let on_path = compute_on_path(leaf_depth, &indexes);

        // leaf layer — identical protocol to generate_multi_proof
        let mut leaf_coset_ids: Vec<usize> = Vec::new();
        for &path_idx in on_path[leaf_depth].iter() {
            let sibling_idx = path_idx ^ 1;
            if on_path[leaf_depth].binary_search(&sibling_idx).is_err() {
                leaf_coset_ids.push(sibling_idx);
            }
        }
        leaf_coset_ids.sort_unstable();

        let mut leaf_copath = Vec::with_capacity(leaf_coset_ids.len());
        for sibling_idx in leaf_coset_ids {
            let digest = self
                .leaf_nodes
                .get(sibling_idx)
                .ok_or_else(|| crate::Error::IncorrectInputLength(self.leaf_nodes.len()))?;
            leaf_copath.push(digest.clone());
        }

        // inner layers: canonical order = depths 1..leaf_depth, ascending index within each depth
        let mut inner_copath: Vec<P::InnerDigest> = Vec::new();
        for depth in 1..leaf_depth {
            for &path_idx in on_path[depth].iter() {
                let sibling_idx = path_idx ^ 1;
                if on_path[depth].binary_search(&sibling_idx).is_err() {
                    let heap_idx = level_index(depth, sibling_idx);
                    let digest = self.non_leaf_nodes.get(heap_idx).ok_or_else(|| {
                        crate::Error::IncorrectInputLength(self.non_leaf_nodes.len())
                    })?;
                    inner_copath.push(digest.clone());
                }
            }
        }

        Ok(implicit::ImplicitCoPath {
            tree_height: d,
            leaf_copath,
            inner_copath,
            leaf_indexes: Vec::from_iter(indexes),
        })
    }

    /// Given the index and new leaf, return the hash of leaf and an updated path in order from root to bottom non-leaf level.
    /// This does not mutate the underlying tree.
    fn updated_path<T: Borrow<P::Leaf>>(
        &self,
        index: usize,
        new_leaf: T,
    ) -> Result<(P::LeafDigest, Vec<P::InnerDigest>), crate::Error> {
        // calculate the hash of leaf
        let new_leaf_hash: P::LeafDigest = P::LeafHash::evaluate(&self.leaf_hash_param, new_leaf)?;

        // calculate leaf sibling hash and locate its position (left or right)
        let (leaf_left, leaf_right) = if index & 1 == 0 {
            // leaf on left
            (&new_leaf_hash, &self.leaf_nodes[index + 1])
        } else {
            (&self.leaf_nodes[index - 1], &new_leaf_hash)
        };

        // calculate the updated hash at bottom non-leaf-level
        let mut path_bottom_to_top = Vec::with_capacity(self.height - 1);
        {
            path_bottom_to_top.push(P::TwoToOneHash::evaluate(
                &self.two_to_one_hash_param,
                P::LeafInnerDigestConverter::convert(leaf_left.clone())?,
                P::LeafInnerDigestConverter::convert(leaf_right.clone())?,
            )?);
        }

        // then calculate the updated hash from bottom to root
        let leaf_index_in_tree = convert_index_to_last_level(index, self.height);
        let mut prev_index = parent(leaf_index_in_tree).unwrap();
        while !is_root(prev_index) {
            let (left_child, right_child) = if is_left_child(prev_index) {
                (
                    path_bottom_to_top.last().unwrap(),
                    &self.non_leaf_nodes[sibling(prev_index).unwrap()],
                )
            } else {
                (
                    &self.non_leaf_nodes[sibling(prev_index).unwrap()],
                    path_bottom_to_top.last().unwrap(),
                )
            };
            let evaluated =
                P::TwoToOneHash::compress(&self.two_to_one_hash_param, left_child, right_child)?;
            path_bottom_to_top.push(evaluated);
            prev_index = parent(prev_index).unwrap();
        }

        debug_assert_eq!(path_bottom_to_top.len(), self.height - 1);
        let path_top_to_bottom: Vec<_> = path_bottom_to_top.into_iter().rev().collect();
        Ok((new_leaf_hash, path_top_to_bottom))
    }

    /// Update the leaf at `index` to updated leaf.
    /// ```tree_diagram
    ///         [A]
    ///        /   \
    ///      [B]    C
    ///     / \   /  \
    ///    D [E] F    H
    ///   .. / \ ....
    ///    [I] J
    /// ```
    /// update(3, {new leaf}) would swap the leaf value at `[I]` and cause a recomputation of `[A]`, `[B]`, and `[E]`.
    pub fn update(&mut self, index: usize, new_leaf: &P::Leaf) -> Result<(), crate::Error> {
        assert!(index < self.leaf_nodes.len(), "index out of range");
        let (updated_leaf_hash, mut updated_path) = self.updated_path(index, new_leaf)?;
        self.leaf_nodes[index] = updated_leaf_hash;
        let mut curr_index = convert_index_to_last_level(index, self.height);
        for _ in 0..self.height - 1 {
            curr_index = parent(curr_index).unwrap();
            self.non_leaf_nodes[curr_index] = updated_path.pop().unwrap();
        }
        Ok(())
    }

    /// Update the leaf and check if the updated root is equal to `asserted_new_root`.
    ///
    /// Tree will not be modified if the check fails.
    pub fn check_update<T: Borrow<P::Leaf>>(
        &mut self,
        index: usize,
        new_leaf: &P::Leaf,
        asserted_new_root: &P::InnerDigest,
    ) -> Result<bool, crate::Error> {
        assert!(index < self.leaf_nodes.len(), "index out of range");
        let (updated_leaf_hash, mut updated_path) = self.updated_path(index, new_leaf)?;
        if &updated_path[0] != asserted_new_root {
            return Ok(false);
        }
        self.leaf_nodes[index] = updated_leaf_hash;
        let mut curr_index = convert_index_to_last_level(index, self.height);
        for _ in 0..self.height - 1 {
            curr_index = parent(curr_index).unwrap();
            self.non_leaf_nodes[curr_index] = updated_path.pop().unwrap();
        }
        Ok(true)
    }
}

/// Returns the height of the tree, given the number of leaves.
#[inline]
fn tree_height(num_leaves: usize) -> usize {
    if num_leaves == 1 {
        return 1;
    }

    (ark_std::log2(num_leaves) as usize) + 1
}
/// Return level-order index encoded in global heap.
/// Node at `depth` (root=0) and position `pos` (0-based at that depth) -> heap index `(1<<depth) - 1 + pos`.
#[inline]
pub(super) fn level_index(depth: usize, pos: usize) -> usize {
    ((1usize << depth) - 1) + pos
}
/// Returns true iff the index represents the root.
#[inline]
fn is_root(index: usize) -> bool {
    index == 0
}

/// Returns the index of the left child, given an index.
#[inline]
fn left_child(index: usize) -> usize {
    2 * index + 1
}

/// Returns the index of the right child, given an index.
#[inline]
fn right_child(index: usize) -> usize {
    2 * index + 2
}

/// Returns the index of the sibling, given an index.
#[inline]
fn sibling(index: usize) -> Option<usize> {
    if index == 0 {
        None
    } else if is_left_child(index) {
        Some(index + 1)
    } else {
        Some(index - 1)
    }
}

/// Returns true iff the given index represents a left child.
#[inline]
fn is_left_child(index: usize) -> bool {
    index % 2 == 1
}

/// Returns the index of the parent, given an index.
#[inline]
fn parent(index: usize) -> Option<usize> {
    if index > 0 {
        Some((index - 1) >> 1)
    } else {
        None
    }
}

#[inline]
fn convert_index_to_last_level(index: usize, tree_height: usize) -> usize {
    index + (1 << (tree_height - 1)) - 1
}

/// Encodes indexes into the packed delta format
#[inline]
fn encode_delta(buffer: &mut Vec<u8>, value: i64) {
    let zigzag = ((value << 1) ^ (value >> 63)) as u64;
    encode_varint(buffer, zigzag);
}

fn decode_delta(bytes: &[u8], cursor: &mut usize) -> Option<i64> {
    let raw = decode_varint(bytes, cursor)?;
    Some(((raw >> 1) as i64) ^ (-((raw & 1) as i64)))
}

#[inline]
fn encode_varint(buffer: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buffer.push(((value as u8) & 0x7F) | 0x80); // MSB = 1 => more bytes follow
        value >>= 7;
    }
    buffer.push(value as u8); // last byte, MSB = 0
}

fn decode_varint(bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;

    while *cursor < bytes.len() {
        let byte = bytes[*cursor];
        *cursor += 1;
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }

    None
}

/// Build the on-path sets A_j from the (sorted, unique) leaf index set I and the leaf depth `d-1`.
/// A_j contains 0-based indices at depth j that lie on the union of all single paths from I to the root.
///
/// Implementation detail:
/// * Uses sorted `Vec<usize>` per level to keep the hot loops linear and cache-friendly.
/// * Each leaf contributes one index per depth; we divide by 2 as we walk up and then sort+dedup.
pub(super) fn compute_on_path(
    depth_leaves: usize,
    indexes: &ark_std::collections::BTreeSet<usize>,
) -> Vec<Vec<usize>> {
    // collect raw indices per depth
    let mut path_sets: Vec<Vec<usize>> = vec![Vec::new(); depth_leaves + 1];
    for &leaf_index in indexes {
        let mut idx = leaf_index;
        let mut depth = depth_leaves;
        loop {
            path_sets[depth].push(idx);
            if depth == 0 {
                break;
            }
            idx >>= 1;
            depth -= 1;
        }
    }

    // sort + dedup each level to get canonical, unique, ascending order
    for level in 0..=depth_leaves {
        let level_vec = &mut path_sets[level];
        level_vec.sort_unstable();
        level_vec.dedup();
    }
    path_sets
}
