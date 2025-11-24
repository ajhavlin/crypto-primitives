use core::convert::TryFrom;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;
use ark_std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
    hash::BuildHasherDefault,
};
use hashbrown::HashMap;

use super::{
    compute_on_path, level_index, Config, DigestConverter, LeafParam, MerkleTree, TwoToOneParam,
    DefaultHasher,
};
use crate::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    Error,
};

type PackedInnerCopath<P> = (usize, usize, Vec<u8>, Vec<<P as Config>::InnerDigest>);

/// CoSet proof used for benchmark data
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Clone(bound = "P: Config"),
    Debug(bound = "P: Config"),
    Default(bound = "P: Config")
)]
pub struct MultiPathV2Bench<P: Config> {
    pub tree_height: usize,
    pub leaf_indexes: Vec<usize>,
    pub leaf_copath: Vec<P::LeafDigest>,
    /// Inner co-path encoded as (start_depth, start_index, packed deltas, digests).
    /// `None` means there are no inner-layer digests required
    pub inner_copath: Option<PackedInnerCopath<P>>,
}

impl<P: Config> MultiPathV2Bench<P> {
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
    ) -> Result<bool, Error> {
        if self.tree_height < 2 {
            return Ok(false);
        }

        // TODO: when multi-proof logic is overhauled, clarify the semantics for empty
        //       batches (this index access panics if `leaf_indexes` is empty)
        // accept valid batch of size 0 proof without path work
        if self.leaf_indexes.is_empty() {
            return Ok(true);
        }

        let d = self.tree_height;
        let leaf_depth = d - 1;

        let mut leaves = leaves.into_iter();
        let mut leaf_level: BTreeMap<usize, P::LeafDigest> = BTreeMap::new();
        for &idx in &self.leaf_indexes {
            let leaf = leaves.next().ok_or_else(|| Error::IncorrectInputLength(self.leaf_indexes.len()))?;
            let leaf_hash = P::LeafHash::evaluate(leaf_hash_params, leaf.borrow())?;
            leaf_level.insert(idx, leaf_hash);
        }
        if leaves.next().is_some() {
            return Err(Error::IncorrectInputLength(self.leaf_indexes.len()));
        }

        // Compute on-path sets A_j and reconstruct expected B*_j = siblings(A_j) \ A_j
        let index_set: BTreeSet<usize> = self.leaf_indexes.iter().copied().collect();
        let on_path = compute_on_path(leaf_depth, &index_set);

        // compute minimal copath at leaf layer (B*_{d-1})
        let mut expected_leaf_coset: Vec<usize> = Vec::new();
        for &path_idx in on_path[leaf_depth].iter() {
            let sibling_idx = path_idx ^ 1;
            if on_path[leaf_depth].binary_search(&sibling_idx).is_err() {
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

        // let mut inner_levels: Vec<CoSetLevel<P>> = (0..d).map(|_| CoSetLevel::new()).collect();
        // prepare inner-level maps for non-on-path siblings and computed parents
        let mut inner_levels: Vec<BTreeMap<usize, P::InnerDigest>> =
            (0..d).map(|_| BTreeMap::new()).collect();

        let mut hash_lut: HashMap<usize, P::InnerDigest, _> =
            HashMap::with_hasher(BuildHasherDefault::<DefaultHasher>::default());

        if let Some((start_depth, start_index, deltas, digests)) = &self.inner_copath {
            if digests.is_empty() {
                if !deltas.is_empty() {
                    return Ok(false);
                }
            } else {
                let mut depth = match i64::try_from(*start_depth) {
                    Ok(value) => value,
                    Err(_) => return Ok(false),
                };
                let mut index = match i64::try_from(*start_index) {
                    Ok(value) => value,
                    Err(_) => return Ok(false),
                };
                let mut cursor = 0usize;
                let mut prev_coord: Option<(usize, usize)> = None;
                let mut push_entry = |depth_i64: i64,
                                      index_i64: i64,
                                      digest: &P::InnerDigest|
                 -> bool {
                    let depth_usize = match usize::try_from(depth_i64) {
                        Ok(v) => v,
                        Err(_) => return false,
                    };
                    let index_usize = match usize::try_from(index_i64) {
                        Ok(v) => v,
                        Err(_) => return false,
                    };
                    if depth_usize == 0 || depth_usize >= d {
                        return false;
                    }
                    if let Some((pd, pi)) = prev_coord {
                        if (depth_usize, index_usize) < (pd, pi) {
                            return false;
                        }
                    }
                    if let Some(existing) = inner_levels[depth_usize].get(&index_usize) {
                        if existing != digest {
                            return false;
                        }
                    } else {
                        inner_levels[depth_usize].insert(index_usize, digest.clone());
                    }
                    let heap_idx = level_index(depth_usize, index_usize);
                    hash_lut.entry(heap_idx).or_insert_with(|| digest.clone());
                    prev_coord = Some((depth_usize, index_usize));
                    true
                };

                if !push_entry(depth, index, &digests[0]) {
                    return Ok(false);
                }

                for digest in digests.iter().skip(1) {
                    let depth_delta = match decode_delta(deltas, &mut cursor) {
                        Some(delta) => delta,
                        None => return Ok(false),
                    };
                    let index_delta = match decode_delta(deltas, &mut cursor) {
                        Some(delta) => delta,
                        None => return Ok(false),
                    };
                    depth = match depth.checked_add(depth_delta) {
                        Some(value) => value,
                        None => return Ok(false),
                    };
                    index = match index.checked_add(index_delta) {
                        Some(value) => value,
                        None => return Ok(false),
                    };
                    if !push_entry(depth, index, digest) {
                        return Ok(false);
                    }
                }

                if cursor != deltas.len() {
                    return Ok(false);
                }
            }
        }

        // Recomputation
        // compute parents at depth d-2 using TwoToOne::evaluate to hash inputs
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
            
        // compute inner layers up to root using TwoToOne::compress to hash inner digests
        for depth in (1..=leaf_depth - 1).rev() {
            let parent_depth = depth - 1;
            for &parent_index in on_path[parent_depth].iter() {
                let left = inner_levels[depth].get(&(parent_index * 2)).cloned();
                let right = inner_levels[depth].get(&(parent_index * 2 + 1)).cloned();
                let (left, right) = match (left, right) {
                    (Some(left), Some(right)) => (left, right),
                    _ => return Ok(false),
                };
                let parent = P::TwoToOneHash::compress(
                    two_to_one_params, 
                    &left, &right,
                )?;
                inner_levels[parent_depth].insert(parent_index, parent.clone());
                // add parent to LUT at heap index
                let heap_idx = level_index(parent_depth, parent_index);
                hash_lut.insert(heap_idx, parent);
            }
        }

        match inner_levels[0].get(&0) {
            Some(h) => {
                Ok(h == root_hash)
            }
            None => Ok(false),
        }
    }
}

impl<P: Config> MerkleTree<P> {
    pub fn generate_multi_proof_v2_bench(
        &self,
        indexes: impl IntoIterator<Item = usize>,
    ) -> Result<MultiPathV2Bench<P>, Error> {
        // pruned and sorted for encoding efficiency
        let indexes: BTreeSet<usize> = indexes.into_iter().collect();
        let d = self.height();

        if indexes.is_empty() {
            return Ok(MultiPathV2Bench {
                tree_height: d,
                leaf_indexes: Vec::new(),
                leaf_copath: Vec::new(),
                inner_copath: None,
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
        for &sibling_idx in &leaf_coset_ids {
            let sibling_digest = self
                .leaf_nodes
                .get(sibling_idx)
                .ok_or_else(|| Error::IncorrectInputLength(self.leaf_nodes.len()))?;
            leaf_copath.push(sibling_digest.clone());
        }

        // inner layers (depth 1..d-2)
        let mut inner_copath_entries: Vec<(usize, usize, P::InnerDigest)> = Vec::new();
        for depth in 1..leaf_depth {
            for &path_idx in on_path[depth].iter() {
                let sibling_idx = path_idx ^ 1;
                if on_path[depth].binary_search(&sibling_idx).is_err() {
                    let heap_idx = level_index(depth, sibling_idx);
                    let sibling_digest = self
                        .non_leaf_nodes
                        .get(heap_idx)
                        .ok_or_else(|| Error::IncorrectInputLength(self.non_leaf_nodes.len()))?;
                    inner_copath_entries.push((depth, sibling_idx, sibling_digest.clone()));
                }
            }
        }
        // canonicalise order
        inner_copath_entries.sort_by_key(|(dpt, idx, _)| (*dpt, *idx));
        let inner_copath = pack_inner_copath::<P>(&inner_copath_entries);

        Ok(MultiPathV2Bench {
            tree_height: d,
            leaf_indexes: Vec::from_iter(indexes),
            leaf_copath,
            inner_copath,
        })
    }
}

fn pack_inner_copath<P: Config>(
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

fn encode_delta(buffer: &mut Vec<u8>, value: i64) {
    let zigzag = ((value << 1) ^ (value >> 63)) as u64;
    encode_varint(buffer, zigzag);
}

fn decode_delta(bytes: &[u8], cursor: &mut usize) -> Option<i64> {
    let raw = decode_varint(bytes, cursor)?;
    Some(((raw >> 1) as i64) ^ (-((raw & 1) as i64)))
}

fn encode_varint(buffer: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buffer.push(((value as u8) & 0x7F) | 0x80);
        value >>= 7;
    }
    buffer.push(value as u8);
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
