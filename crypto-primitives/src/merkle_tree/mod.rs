#![allow(clippy::needless_range_loop)]

/// Defines a trait to chain two types of CRHs.
use crate::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    sponge::Absorb,
    Error,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;
use ark_std::{
    borrow::Borrow,
    collections::{BTreeSet, BTreeMap},
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
type DefaultHasher = ahash::AHasher;

#[cfg(not(all(
    target_has_atomic = "8",
    target_has_atomic = "16",
    target_has_atomic = "32",
    target_has_atomic = "64",
    target_has_atomic = "ptr"
)))]
type DefaultHasher = fnv::FnvHasher;

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
///         [A]
///        /   \
///      [B]    C
///     / \    /  \
///    D [E]  F    H
///  ... / \ / \ ....
///    [I] J L  M
/// ```
///  Suppose we want to prove I and J, then:
///     `leaf_indexes` is: `[2,3]` (indexes in Merkle Tree leaves vector)
///     `leaf_siblings_hashes`: `[J,I]`
///     `auth_paths_prefix_lenghts`: `[0,2]`
///     `auth_paths_suffixes`: `[ [C,D], []]`
///  We can reconstruct the paths incrementally:
///  First, we reconstruct the first path. The prefix length is 0, hence we do not have any prefix encoding.
///  The path is thus `[C,D]`.
///  Once the first path is verified, we can reconstruct the second path.
///  The prefix length of 2 means that the path prefix will be `previous_path[:2] -> [C,D]`.
///  Since the Merkle Tree branch is the same, the authentication path is the same (which means in this case that there is no suffix).
///  The second path is hence `[C,D] + []` (i.e., plus the empty suffix). We can verify the second path as the first one.

#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Clone(bound = "P: Config"),
    Debug(bound = "P: Config"),
    Default(bound = "P: Config")
)]
pub struct MultiPath<P: Config> {
    /// For node i, stores the hash of node i's sibling
    pub leaf_siblings_hashes: Vec<P::LeafDigest>,
    /// For node i path, stores at index i the prefix length of the path, for Incremental encoding
    pub auth_paths_prefix_lenghts: Vec<usize>,
    /// For node i path, stores at index i the suffix of the path for Incremental Encoding (as vector of symbols to be resolved with self.lut). Order is from higher layer to lower layer (does not include root node).
    pub auth_paths_suffixes: Vec<Vec<P::InnerDigest>>,
    /// stores the leaf indexes of the nodes to prove
    pub leaf_indexes: Vec<usize>,
}

impl<P: Config> MultiPath<P> {
    /// Verify that leaves are at `self.leaf_indexes` of the merkle tree.
    /// Note that the order of the leaves hashes should match the leaves respective indexes
    /// * `leaf_size`: leaf size in number of bytes
    ///
    /// `verify` infers the tree height by setting `tree_height = self.auth_paths_suffixes[0].len() + 2`
    pub fn verify<L: Borrow<P::Leaf> + Clone>(
        &self,
        leaf_hash_params: &LeafParam<P>,
        two_to_one_params: &TwoToOneParam<P>,
        root_hash: &P::InnerDigest,
        leaves: impl IntoIterator<Item = L>,
    ) -> Result<bool, crate::Error> {
        let tree_height = self.auth_paths_suffixes[0].len() + 2;
        let mut leaves = leaves.into_iter();

        // LookUp table to speedup computation avoid redundant hash computations
        let mut hash_lut: HashMap<usize, P::InnerDigest, _> =
            HashMap::with_hasher(BuildHasherDefault::<DefaultHasher>::default());

        // init prev path for decoding
        let mut prev_path: Vec<_> = self.auth_paths_suffixes[0].clone();

        for i in 0..self.leaf_indexes.len() {
            let leaf_index = self.leaf_indexes[i];
            let leaf = leaves.next().unwrap();
            let leaf_sibling_hash = &self.leaf_siblings_hashes[i];

            // decode i-th auth path
            let auth_path = prefix_decode_path(
                &prev_path,
                self.auth_paths_prefix_lenghts[i],
                &self.auth_paths_suffixes[i],
            );
            // update prev path for decoding next one
            prev_path = auth_path.clone();

            let claimed_leaf_hash = P::LeafHash::evaluate(&leaf_hash_params, leaf.clone())?;
            let (left_child, right_child) =
                select_left_right_child(leaf_index, &claimed_leaf_hash, &leaf_sibling_hash)?;
            // check hash along the path from bottom to root

            // leaf layer to inner layer conversion
            let left_child = P::LeafInnerDigestConverter::convert(left_child)?;
            let right_child = P::LeafInnerDigestConverter::convert(right_child)?;

            // we will use `index` variable to track the position of path
            let mut index = leaf_index;
            let mut index_in_tree = convert_index_to_last_level(leaf_index, tree_height);
            index >>= 1;
            index_in_tree = parent(index_in_tree).unwrap();

            let mut curr_path_node = hash_lut.entry(index_in_tree).or_insert_with(|| {
                P::TwoToOneHash::evaluate(&two_to_one_params, left_child, right_child).unwrap()
            });

            // Check levels between leaf level and root
            for level in (0..auth_path.len()).rev() {
                // check if path node at this level is left or right
                let (left, right) =
                    select_left_right_child(index, curr_path_node, &auth_path[level])?;
                // update curr_path_node
                index >>= 1;
                index_in_tree = parent(index_in_tree).unwrap();
                curr_path_node = hash_lut.entry(index_in_tree).or_insert_with(|| {
                    P::TwoToOneHash::compress(&two_to_one_params, left, right).unwrap()
                });
            }

            // check if final hash is root
            if curr_path_node != root_hash {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The position of on_path node in `leaf_and_sibling_hash` and `non_leaf_and_sibling_hash_path`.
    /// `position[i]` is 0 (false) iff `i`th on-path node from top to bottom is on the left.
    ///
    /// This function simply converts every index in `self.leaf_indexes` to boolean array in big endian form.
    #[allow(unused)] // this function is actually used when r1cs feature is on
    fn position_list(&'_ self) -> impl '_ + Iterator<Item = Vec<bool>> {
        let path_len = self.auth_paths_suffixes[0].len();

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
///     `leaf_indexes` is: `[2,3]` (indexes in Merkle Tree leaves vector)
///     `leaf_copath`: `[]`
///     `inner_copath`: `[(2,0,D), (1,1,C)]`
/// 
///     ---- Legacy fields ----
///     `leaf_siblings_hashes`: `[J,I]`
///     `auth_paths_prefix_lenghts`: `[0,2]`
///     `auth_paths_suffixes`: `[ [C,D], []]`
/// 
///  We can reconstruct upfront the minimal copath needed for the proof:
///  First, we reconstruct the minimal copath at the leaf layer (`depth = tree_height-1`). 
///  This is only those sibling leaf digests that are required to complete parents of on-path leaves but are not themselves on-path.
///  The leaf copath is thus `[J,I]/[I,J]=[]`.
///  We then repeat this for each inner layer, computing only the non-on-path siblings needed to complete parents of the union of all single paths.
///  The inner copath digests are stored as (depth, index, digest) tuples ordered by (depth, index).
///  Thus, inner copath is `[(2,0,D), (1,1,C)]`.
///  Intuitively, CoSet transmits only what's missing to recompute every parent on the shared union-of-paths.
///  
/// ---- Legacy prefix encoding (kept for compatibility): ----
///  We can reconstruct the paths incrementally:
///  First, we reconstruct the first path. The prefix length is 0, hence we do not have any prefix encoding.
///  The path is thus `[C,D]`.
///  Once the first path is verified, we can reconstruct the second path.
///  The prefix length of 2 means that the path prefix will be `previous_path[:2] -> [C,D]`.
///  Since the Merkle Tree branch is the same, the authentication path is the same (which means in this case that there is no suffix).
///  The second path is hence `[C,D] + []` (i.e., plus the empty suffix). We can verify the second path as the first one.

#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Clone(bound = "P: Config"),
    Debug(bound = "P: Config"),
    Default(bound = "P: Config")
)]
pub struct MultiPathV2<P: Config> {
    /// ---- MultiPathV2 new fields ----
    /// stores the height of the tree (>= 2) to drive CoSet decoding
    pub tree_height: usize,
    /// TODO: reorder leaf_indexes last in proof for legacy use compatibility
    /// stores the leaf indexes of the nodes to prove
    pub leaf_indexes: Vec<usize>,
    /// For leaf layer, stores co-path digests (B*_{d-1}) in ascending sibling index order
    pub leaf_copath: Vec<P::LeafDigest>,
    /// For inner layers, stores co-path entries as (depth, index, digest) tuples ordered by (depth, index)
    pub inner_copath: Vec<(usize, usize, P::InnerDigest)>,
    
    /// ---- Legacy fields (kept for compatibility/tests) ----
    /// For node i, stores the hash of node i's sibling
    pub leaf_siblings_hashes: Vec<P::LeafDigest>,
    /// For node i path, stores at index i the prefix length of the path, for Incremental encoding
    pub auth_paths_prefix_lenghts: Vec<usize>,
    /// For node i path, stores at index i the suffix of the path for Incremental Encoding (as vector of symbols to be resolved with self.lut). Order is from higher layer to lower layer (does not include root node).
    pub auth_paths_suffixes: Vec<Vec<P::InnerDigest>>,
}

impl<P: Config> MultiPathV2<P> {
    /// Verify that leaves are at `self.leaf_indexes` of the merkle tree.
    /// Note that the order of the leaves hashes should match the leaves respective indexes
    /// * `leaf_size`: leaf size in number of bytes
    ///
    /// `verify` infers the tree height by setting `tree_height = self.auth_paths_suffixes[0].len() + 2`
    pub fn verify<L: Borrow<P::Leaf> + Clone>(
        &self,
        leaf_hash_params: &LeafParam<P>,
        two_to_one_params: &TwoToOneParam<P>,
        root_hash: &P::InnerDigest,
        leaves: impl IntoIterator<Item = L>,
    ) -> Result<bool, crate::Error> {
        // TODO: when multi-proof logic is overhauled, clarify the semantics for empty
        //       batches (this index access panics if `leaf_indexes` is empty)
        let have_coset = 
            self.tree_height >= 2 && 
            (!self.leaf_indexes.is_empty() // accept valid batch of size 0 proof without path work
             || !self.inner_copath.is_empty() 
             || !self.leaf_copath.is_empty());

        if have_coset {
            let d = self.tree_height;
            let leaf_depth = d - 1;
            if d < 2 {
                return Ok(false);
            }

            // hash opened leaves and build map containing all leaf digests needed at bottom layer
            let mut leaves = leaves.into_iter();
            let mut leaf_level: BTreeMap<usize, P::LeafDigest> = BTreeMap::new(); 
            for &idx in &self.leaf_indexes {
                let leaf = leaves.next().ok_or_else(|| crate::Error::IncorrectInputLength(self.leaf_indexes.len()))?;
                let leaf_hash = P::LeafHash::evaluate(leaf_hash_params, leaf.borrow())?;
                leaf_level.insert(idx, leaf_hash);
            }
            if leaves.next().is_some() {
                return Err(crate::Error::IncorrectInputLength(self.leaf_indexes.len()));
            }

            // Compute on-path sets A_j and reconstruct expected B*_j = siblings(A_j) \ A_j
            let index_set: BTreeSet<usize> = self.leaf_indexes.iter().copied().collect();
            let on_path = compute_on_path(leaf_depth, &index_set); // holds indices of on-path nodes at depth d

            // compute minimal copath at leaf layer (B*_{d-1})
            let mut expected_leaf_coset: Vec<usize> = Vec::new();
            for &path_idx in on_path[leaf_depth].iter() {
                let sibling_idx = path_idx ^ 1;
                if !on_path[leaf_depth].contains(&sibling_idx) {
                    expected_leaf_coset.push(sibling_idx); // copath element needed for proof
                }
            }
            expected_leaf_coset.sort_unstable(); // canonical order

            if expected_leaf_coset.len() != self.leaf_copath.len() {
                return Ok(false);
            }

            for (sibling_idx, sibling_digest) in expected_leaf_coset.into_iter().zip(self.leaf_copath.iter()) {
                match leaf_level.get(&sibling_idx) {
                    Some(existing) if existing != sibling_digest => return Ok(false), // digest must match new one
                    _ => {
                        leaf_level.insert(sibling_idx, sibling_digest.clone());
                    }
                }
            }

            // prepare inner-level maps for non-on-path siblings and computed parents
            let mut inner_levels: Vec<BTreeMap<usize, P::InnerDigest>> =
                (0..d).map(|_| BTreeMap::new()).collect();

            // LookUp table to speedup computation avoid redundant hash computations
            let mut hash_lut: HashMap<usize, P::InnerDigest, _> =
                HashMap::with_hasher(BuildHasherDefault::<DefaultHasher>::default());

            for &(depth, idx, ref copath_digest) in &self.inner_copath {
                if depth == 0 || depth >= d {
                    return Ok(false);
                }
                // store the sibling digest at its depth/index
                if let Some(existing) = inner_levels[depth].get(&idx) {
                    if existing != copath_digest {
                        return Ok(false);
                    }
                } else {
                    inner_levels[depth].insert(idx, copath_digest.clone());
                }
                // seed LUT with known siblings
                let heap_idx = level_index(depth, idx);
                hash_lut.entry(heap_idx).or_insert_with(|| copath_digest.clone());
            }

            // Recomputation
            // compute parents at depth d-2 using TwoToOne::evaluate to hash inputs
            for &parent_index in on_path[leaf_depth - 1].iter() {
                let left = leaf_level.get(&(parent_index * 2)).cloned();
                let right = leaf_level.get(&(parent_index * 2 + 1)).cloned();
                let (left, right) = match (left, right) { (Some(left), Some(right)) => (left, right), _ => return Ok(false) };
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

            // compute inner layers up to root using TwoToOne::compress to hash inner digests
            for depth in (1..=leaf_depth - 1).rev() {
                let parent_depth = depth - 1;
                for &parent_index in on_path[parent_depth].iter() {
                    let left = inner_levels[depth].get(&(parent_index * 2)).cloned();
                    let right = inner_levels[depth].get(&(parent_index * 2 + 1)).cloned();
                    let (left, right) = match (left, right) { (Some(left), Some(right)) => (left, right), _ => return Ok(false) };
                    let parent = P::TwoToOneHash::compress(
                        two_to_one_params, 
                        &left, 
                        &right,
                    )?;
                    inner_levels[parent_depth].insert(parent_index, parent.clone());
                    // add parent to LUT at heap index
                    let heap_idx = level_index(parent_depth, parent_index);
                    hash_lut.insert(heap_idx, parent);
                }
            }

            // check root
            match inner_levels[0].get(&0) {
                Some(h) => {
                    Ok(h == root_hash)
                }
                None => Ok(false),
            }
        } else {
            // --- Legacy prefix-decoder path ---
            let tree_height = self.auth_paths_suffixes.get(0).map(|v| v.len()).unwrap_or(0) + 2;
            let mut leaves = leaves.into_iter();

            // LookUp table to speedup computation avoid redundant hash computations
            let mut hash_lut: hashbrown::HashMap<usize, P::InnerDigest, _> =
                hashbrown::HashMap::with_hasher(BuildHasherDefault::<DefaultHasher>::default());

            // init prev path for decoding
            let mut prev_path: Vec<_> = self.auth_paths_suffixes[0].clone();

            for i in 0..self.leaf_indexes.len() {
                let leaf_index = self.leaf_indexes[i];
                let leaf = leaves.next().unwrap();
                let leaf_sibling_hash = &self.leaf_siblings_hashes[i];

                // decode i-th auth path
                let auth_path = prefix_decode_path(
                    &prev_path,
                    self.auth_paths_prefix_lenghts[i],
                    &self.auth_paths_suffixes[i],
                );
                // update prev path for decoding next one
                prev_path = auth_path.clone();

                let claimed_leaf_hash = P::LeafHash::evaluate(&leaf_hash_params, leaf.clone())?;
                let (left_child, right_child) =
                    select_left_right_child(leaf_index, &claimed_leaf_hash, &leaf_sibling_hash)?;
                // check hash along the path from bottom to root

                // leaf layer to inner layer conversion
                let left_child = P::LeafInnerDigestConverter::convert(left_child)?;
                let right_child = P::LeafInnerDigestConverter::convert(right_child)?;

                // we will use `index` variable to track the position of path
                let mut index = leaf_index;
                let mut index_in_tree = convert_index_to_last_level(leaf_index, tree_height);
                index >>= 1;
                index_in_tree = parent(index_in_tree).unwrap();

                let mut curr_path_node = hash_lut.entry(index_in_tree).or_insert_with(|| {
                    P::TwoToOneHash::evaluate(&two_to_one_params, left_child, right_child).unwrap()
                });

                // Check levels between leaf level and root
                for level in (0..auth_path.len()).rev() {
                    // check if path node at this level is left or right
                    let (left, right) =
                        select_left_right_child(index, curr_path_node, &auth_path[level])?;
                    // update curr_path_node
                    index >>= 1;
                    index_in_tree = parent(index_in_tree).unwrap();
                    curr_path_node = hash_lut.entry(index_in_tree).or_insert_with(|| {
                        P::TwoToOneHash::compress(&two_to_one_params, left, right).unwrap()
                    });
                }

                // check if final hash is root
                if curr_path_node != root_hash {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }

    /// The position of on_path node in `leaf_and_sibling_hash` and `non_leaf_and_sibling_hash_path`.
    /// `position[i]` is 0 (false) iff `i`th on-path node from top to bottom is on the left.
    ///
    /// This function simply converts every index in `self.leaf_indexes` to boolean array in big endian form.
    #[allow(unused)] // this function is actually used when r1cs feature is on
    fn position_list(&'_ self) -> impl '_ + Iterator<Item = Vec<bool>> {
        let path_len = self.auth_paths_suffixes[0].len();

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

    /// Returns a MultiPath (multiple authentication paths in compressed form, with Front Incremental Encoding),
    /// from every leaf to root.
    /// Note that for compression efficiency, the indexes are internally sorted.
    /// For sorted indexes, MultiPath contains:
    /// `2*( (num_leaves.log2()-1).pow(2) - (num_leaves.log2()-2) )`
    /// instead of
    /// `num_leaves*(num_leaves.log2()-1)`
    /// When verifying the proof, leaves hashes should be supplied in order, that is:
    /// ```ignore
    /// let ordered_leaves: Vec<_> = self.leaf_indexes.into_iter().map(|i| leaves[i]).collect();
    /// ```
    pub fn generate_multi_proof(
        &self,
        indexes: impl IntoIterator<Item = usize>,
    ) -> Result<MultiPath<P>, crate::Error> {
        // pruned and sorted for encoding efficiency
        let indexes: BTreeSet<usize> = indexes.into_iter().collect();

        //let auth_paths = Vec::with_capacity(indexes.len());
        let mut auth_paths_prefix_lenghts: Vec<usize> = Vec::with_capacity(indexes.len());
        let mut auth_paths_suffixes: Vec<Vec<P::InnerDigest>> = Vec::with_capacity(indexes.len());

        let mut leaf_siblings_hashes = Vec::with_capacity(indexes.len());

        let mut prev_path = Vec::new();

        for index in &indexes {
            leaf_siblings_hashes.push(self.get_leaf_sibling_hash(*index));

            let path = self.compute_auth_path(*index);

            // incremental encoding
            let (prefix_len, suffix) = prefix_encode_path(&prev_path, &path);
            auth_paths_prefix_lenghts.push(prefix_len);
            auth_paths_suffixes.push(suffix);
            prev_path = path;
        }

        Ok(MultiPath {
            leaf_indexes: Vec::from_iter(indexes),
            auth_paths_prefix_lenghts,
            auth_paths_suffixes,
            leaf_siblings_hashes,
        })
    }

    /// Returns a MultiPathV2 (a compressed membership proof for a set of leaves), 
    /// sufficient to verify each leaf up to the root.
    /// Note that for compatibility, indexes are internally sorted and legacy prefix fields still populated.
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
    /// * `inner_copath`: the inner co-path as `(depth, index, digest)` tuples ordered by `(depth, index)`.
    ///
    /// The lagacy prefix fields (`auth_paths_prefix_lenghts`, `auth_paths_suffixes`, and `leaf_siblings_hashes`) 
    /// are still filled so existing tests and callers that expect prefix decoding continue to work.
    /// 
    /// When verifying the proof, leaves hashes should be supplied in order of `leaf_indexes`, that is:
    /// ```ignore
    /// let ordered_leaves: Vec<_> = self.leaf_indexes.into_iter().map(|i| leaves[i]).collect();
    /// ```
    /// Notes:
    /// * Empty input (`indexes` is empty) returns a structurally valid empty proof carrying `tree_height`,
    ///   and verification succeeds vacuously against the claimed root.
    pub fn generate_multi_proof_v2(
        &self,
        indexes: impl IntoIterator<Item = usize>,
    ) -> Result<MultiPathV2<P>, crate::Error> {
        // pruned and sorted for encoding efficiency
        let indexes: BTreeSet<usize> = indexes.into_iter().collect();
        let d = self.height();

        // TODO: should empty query return structurally valid empty proof
        if indexes.is_empty() {
            return Ok(MultiPathV2 {
                tree_height: d,
                leaf_indexes: Vec::new(),
                leaf_copath: Vec::new(),
                inner_copath: Vec::new(),
                // legacy
                leaf_siblings_hashes: Vec::new(),
                auth_paths_prefix_lenghts: Vec::new(),
                auth_paths_suffixes: Vec::new(),
            });
        }

        // legacy       
        let mut auth_paths_prefix_lenghts = Vec::with_capacity(indexes.len());
        let mut auth_paths_suffixes: Vec<Vec<P::InnerDigest>> = Vec::with_capacity(indexes.len());
       
        let mut leaf_siblings_hashes = Vec::with_capacity(indexes.len());
        
        let mut prev_path = Vec::new();
        // end of legacy

        let leaf_depth = d - 1;
        let mut leaf_candidates: BTreeMap<(usize /*depth*/, usize /*idx*/), P::LeafDigest> =
            BTreeMap::new();
        let mut inner_candidates: BTreeMap<(usize /*depth*/, usize /*idx*/), P::InnerDigest> =
            BTreeMap::new();

        // TODO: loop over index in &indexes with ref to *index 
        // or switch to &i in indexes.iter() with ref to i and promise ?
        for &i in indexes.iter() {
            let path = self.generate_proof(i)?;
            
            // Legacy prefix-encoding (for compatibility)
            let prefix_len = {
                let l = prev_path
                    .iter()
                    .zip(path.auth_path.iter())
                    .take_while(|(a, b)| a == b)
                    .count();
                l
            };
            let suffix = path.auth_path[prefix_len..].to_vec();
            auth_paths_prefix_lenghts.push(prefix_len);
            auth_paths_suffixes.push(suffix);
            prev_path = path.auth_path.clone();

            leaf_siblings_hashes.push(path.leaf_sibling_hash.clone());
            // end of legacy

            // CoSet candidates at leaf layer: sibling at depth d-1 is i xor 1
            let sib_leaf_idx = i ^ 1;
            leaf_candidates
                .entry((leaf_depth, sib_leaf_idx))
                .or_insert(path.leaf_sibling_hash);

            // CoSet candidates on inner layers
            for (offset, digest) in path.auth_path.into_iter().enumerate() {
                let depth = offset + 1; // inner depths are 1..(d-2)
                let shift = leaf_depth - depth;
                let on_path_index = if shift == 0 { i } else { i >> shift };
                let sibling_index = on_path_index ^ 1;
                inner_candidates
                    .entry((depth, sibling_index))
                    .or_insert(digest);
            }
        }

        // Compute on-path sets A_j and then minimal co-path B*_j = siblings(A_j) \ A_j
        let on_path = compute_on_path(leaf_depth, &indexes);

        // leaf layer (depth = d-1)
        let mut leaf_coset_ids: BTreeSet<usize> = BTreeSet::new();
        for &path_idx in on_path[leaf_depth].iter() {
            let sibling_idx = path_idx ^ 1;
            if !on_path[leaf_depth].contains(&sibling_idx) {
                leaf_coset_ids.insert(sibling_idx);
            }
        }

        let mut leaf_copath = Vec::with_capacity(leaf_coset_ids.len());
        for sibling_idx in leaf_coset_ids.iter().copied() {
            if let Some(sibling_digest) = leaf_candidates.get(&(leaf_depth, sibling_idx)) {
                leaf_copath.push(sibling_digest.clone());
            } else {
                return Err(crate::Error::IncorrectInputLength(self.leaf_nodes.len()));
            }
        }

        // inner layers (depth 1..d-2)
        let mut inner_copath = Vec::new();
        for depth in 1..leaf_depth {
            for &path_idx in on_path[depth].iter() {
                let sibling_idx = path_idx ^ 1;
                if !on_path[depth].contains(&sibling_idx) {
                    if let Some(sibling_digest) = inner_candidates.get(&(depth, sibling_idx)) {
                        inner_copath.push((depth, sibling_idx, sibling_digest.clone()));
                    } else {
                        return Err(crate::Error::IncorrectInputLength(self.leaf_nodes.len()));
                    }
                }
            }
        }
        // canonicalise order
        inner_copath.sort_by_key(|(dpt, idx, _)| (*dpt, *idx));

        // TODO: later remove trace
        Ok(MultiPathV2 {
            tree_height: d,
            leaf_indexes: Vec::from_iter(indexes),
            leaf_copath,
            inner_copath,
            // legacy fields still populated for tests
            leaf_siblings_hashes,
            auth_paths_prefix_lenghts,
            auth_paths_suffixes,
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
fn level_index(depth: usize, pos: usize) -> usize {
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

/// Encodes path with Incremental Encoding by comparing with prev_path
/// Returns the prefix length and the suffix to append during decoding
/// Example:
/// If `prev_path` is vec![C,D] and `path` is vec![C,E] (where C,D,E are hashes)
/// `prefix_encode_path` returns 1,vec![E]

#[inline]
fn prefix_encode_path<T>(prev_path: &Vec<T>, path: &Vec<T>) -> (usize, Vec<T>)
where
    T: Eq + Clone,
{
    let prefix_length = prev_path
        .iter()
        .zip(path.iter())
        .take_while(|(a, b)| a == b)
        .count();

    (prefix_length, path[prefix_length..].to_vec())
}

fn prefix_decode_path<T>(prev_path: &Vec<T>, prefix_len: usize, suffix: &Vec<T>) -> Vec<T>
where
    T: Eq + Clone,
{
    if prefix_len == 0 {
        suffix.clone()
    } else {
        vec![prev_path[0..prefix_len].to_vec(), suffix.clone()].concat()
    }
}

/// Build the on-path sets A_j from the (sorted, unique) leaf index set I and the leaf depth `d-1`.
/// A_j contains 0-based indices at depth j that lie on the union of all single paths from I to the root.
fn compute_on_path(depth_leaves: usize, indexes: &ark_std::collections::BTreeSet<usize>)
    -> Vec<ark_std::collections::BTreeSet<usize>>
{
    use ark_std::collections::BTreeSet;
    let mut path_sets = vec![BTreeSet::new(); depth_leaves + 1];
    for &leaf_index in indexes.iter() {
        for depth in 0..=depth_leaves {
            let shift = depth_leaves - depth;
            let path_index = if shift == 0 { leaf_index } else { leaf_index >> shift };
            path_sets[depth].insert(path_index);
        }
    }
    path_sets
}
