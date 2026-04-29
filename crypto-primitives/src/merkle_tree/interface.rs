//! Simplified high-level interface for the Merkle tree.
//!
//! Both prover and verifier construct `scheme` with the same parameters:
//!
//! Prover: build and commit
//! `let scheme = MerkleTree::<P>::new(&leaf_params, &inner_params, leaves)?;`
//! `let committed = scheme.commit(message)?;`
//! `let root  = committed.root();`              // publish
//! `let proof = committed.open([3, 7, 12]);`    // open a subset
//!
//! Verifier: reconstruct scheme and check
//! `let scheme  = MerkleTree::<P>::blank(&leaf_params, &inner_params, height)?;`
//! `let opening = Opening::new(vec![3, 7, 12], vec![leaf3, leaf7, leaf12]);`
//! `let ok: bool = scheme.check(&root, &opening, &proof));`
//! ```
//!
//! Opening and Proof both sort and dedup their index lists automatically at construction time.
//!
//! Proof compression
//! Proof is produced in the coset-optimised (compressed) format by default.
//! To expand the proof (one sibling per leaf, useful for circuits that
//! process each path independently) call `Proof::expand`; to compress back, call
//! `Proof::compress`.

use super::{Committed, Config, LeafParam, MerkleTree, Opening, Proof, TwoToOneParam};
use crate::Error;
use ark_std::borrow::Borrow;

/// High-level interface over a configured Merkle tree instance.
///
/// Implemented by `MerkleTree<P>` for any `Config` `P`.
pub trait MerkleScheme: Sized {
    /// The hash configuration for this scheme.
    type Config: Config;

    /// Construct a scheme from hash parameters and an initial set of leaves.
    ///
    /// The leaf count must be a power of two and ≥ 2.
    fn new<L: AsRef<<Self::Config as Config>::Leaf> + Send>(
        leaf_hash_param: &LeafParam<Self::Config>,
        two_to_one_hash_param: &TwoToOneParam<Self::Config>,
        leaves: impl IntoIterator<Item = L>,
    ) -> Result<Self, Error>;

    /// Construct a scheme over a tree of `2^(height-1)` default (zero) leaves.
    ///
    /// `height` must be ≥ 2.  Use this on the verifier side when no leaf data is needed.
    fn blank(
        leaf_hash_param: &LeafParam<Self::Config>,
        two_to_one_hash_param: &TwoToOneParam<Self::Config>,
        height: usize,
    ) -> Result<Self, Error>;

    /// Commit to a full ordered message of leaves.
    ///
    /// Returns a trapdoor the prover uses to open arbitrary subsets of leaves via
    /// `Committed::open`.  The public commitment is `Committed::root`.
    fn commit<L: AsRef<<Self::Config as Config>::Leaf> + Send>(
        &self,
        message: impl IntoIterator<Item = L>,
    ) -> Result<Committed<Self::Config>, Error>;

    /// Verify a batch opening proof.
    ///
    /// Returns `false` when:
    /// - `opening.indices()` != `proof.leaf_indexes()` (wrong index set),
    /// - the proof is structurally invalid (wrong digest count, out-of-bounds index, etc.), or
    /// - the recomputed root does not match `root_hash`.
    ///
    /// Both Opening and Proof normalise their index lists at construction time, so
    /// index ordering at the call site does not matter.
    fn check<L: Borrow<<Self::Config as Config>::Leaf> + Clone>(
        &self,
        root_hash: &<Self::Config as Config>::InnerDigest,
        opening: &Opening<L>,
        proof: &Proof<Self::Config>,
    ) -> bool;
}

impl<P: Config> MerkleScheme for MerkleTree<P> {
    type Config = P;

    fn new<L: AsRef<P::Leaf> + Send>(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        leaves: impl IntoIterator<Item = L>,
    ) -> Result<Self, Error> {
        MerkleTree::new(leaf_hash_param, two_to_one_hash_param, leaves)
    }

    fn blank(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        height: usize,
    ) -> Result<Self, Error> {
        MerkleTree::blank(leaf_hash_param, two_to_one_hash_param, height)
    }

    fn commit<L: AsRef<P::Leaf> + Send>(
        &self,
        message: impl IntoIterator<Item = L>,
    ) -> Result<Committed<P>, Error> {
        #[cfg(not(feature = "parallel"))]
        {
            MerkleTree::commit(self, message)
        }
        #[cfg(feature = "parallel")]
        {
            MerkleTree::commit(self, message.into_iter().collect::<Vec<_>>())
        }
    }

    fn check<L: Borrow<P::Leaf> + Clone>(
        &self,
        root_hash: &P::InnerDigest,
        opening: &Opening<L>,
        proof: &Proof<P>,
    ) -> bool {
        MerkleTree::check(self, root_hash, opening, proof)
    }
}
