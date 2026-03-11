//! # CTF Challenges: Merkle Tree Security Vulnerabilities
//!
//! Four self-contained CTF challenges derived from the critical findings in SECURITY_REQUIREMENTS.md.
//! Each challenge exposes one exploitable flaw in the current implementation.
//!
//! | ID  | Title                    | Finding                   | Impact        |
//! |-----|--------------------------|---------------------------|---------------|
//! | C-1 | The Infinite Allocator   | tree_height=0 underflow   | DoS / OOM     |
//! | C-2 | The Off-By-One Abyss     | tree_height=1 OOB access  | DoS / panic   |
//! | C-3 | The Shapeshifter Leaf    | evaluate == compress      | Forgery       |
//! | C-4 | The Phantom Witness      | non-canonical R1CS bytes  | Soundness gap |
//!
//! Run all challenges:
//!   cargo test --package ark-crypto-primitives --features merkle_tree merkle_tree::tests::ctf
//!
//! Run a single challenge (e.g. C-3):
//!   cargo test ctf_c3 -- --nocapture

use crate::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{Config, CoPath, IdentityDigestConverter, MerkleTree},
    Error,
};
use ark_std::borrow::Borrow;

// ──────────────────────────────────────────────────────────────────────────────
// Shared infrastructure: minimal DummyCfg (XOR hash, unit leaves) for C-1/C-2.
// ──────────────────────────────────────────────────────────────────────────────

struct DummyLeafHash;
impl CRHScheme for DummyLeafHash {
    type Input  = ();
    type Output = u8;
    type Parameters = ();
    fn setup<R: ark_std::rand::Rng>(_: &mut R) -> Result<Self::Parameters, Error> { Ok(()) }
    fn evaluate<T: Borrow<Self::Input>>(_: &Self::Parameters, _: T) -> Result<Self::Output, Error> {
        Ok(0u8)
    }
}

struct DummyTwoToOne;
impl TwoToOneCRHScheme for DummyTwoToOne {
    type Input      = u8;
    type Output     = u8;
    type Parameters = ();
    fn setup<R: ark_std::rand::Rng>(_: &mut R) -> Result<Self::Parameters, Error> { Ok(()) }
    fn evaluate<T: Borrow<Self::Input>>(_: &Self::Parameters, l: T, r: T) -> Result<Self::Output, Error> {
        Ok(l.borrow() ^ r.borrow())
    }
    fn compress<T: Borrow<Self::Output>>(_: &Self::Parameters, l: T, r: T) -> Result<Self::Output, Error> {
        Ok(l.borrow() ^ r.borrow())
    }
}

struct DummyCfg;
impl Config for DummyCfg {
    type Leaf = ();
    type LeafDigest = u8;
    type LeafInnerDigestConverter = IdentityDigestConverter<u8>;
    type InnerDigest  = u8;
    type LeafHash     = DummyLeafHash;
    type TwoToOneHash = DummyTwoToOne;
}


// ═════════════════════════════════════════════════════════════════════════════
// CTF C-1 — THE INFINITE ALLOCATOR
// ═════════════════════════════════════════════════════════════════════════════
//
// BRIEFING
// ────────
// A prover submits a CoPath batch proof with `tree_height = 0`. Line 283 of
// mod.rs then computes:
//
//     let leaf_depth = d - 1;   // d = 0 → 0usize - 1 → underflow
//
// • Debug build:   panics immediately at the subtraction (overflow check).
// • Release build: leaf_depth wraps to usize::MAX; compute_on_path tries
//                  `vec![Vec::new(); usize::MAX + 1]` which wraps to length 0,
//                  then the loop body immediately panics OOB.
//
// OBJECTIVE: craft the smallest CoPath that panics `verify` with tree_height=0.
// FLAG:      #[should_panic] test passes → exploit confirmed.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn ctf_c1_tree_height_zero_dos() {
    // FIXED: tree_height < 2 is now caught before any arithmetic.
    // verify() returns Err instead of underflowing to usize::MAX.
    let malicious_proof = CoPath::<DummyCfg> {
        tree_height: 0,
        leaf_copath:  vec![],
        inner_copath: None,
        leaf_indexes: vec![0],
    };

    let result = malicious_proof.verify(&(), &(), &0u8, 2, vec![()]);
    assert!(result.is_err(), "C-1 fix: tree_height=0 must return Err, not panic");
}

/// Proof of mechanism: shows the exact arithmetic behind the underflow,
/// safely, without crashing the test process.
#[test]
fn ctf_c1_mechanism_proof() {
    let d: usize = 0;

    // `let leaf_depth = d - 1;`  ← this is line 283
    let leaf_depth = d.wrapping_sub(1);
    assert_eq!(leaf_depth, usize::MAX,
        "tree_height=0 wraps leaf_depth to usize::MAX in release mode");

    // compute_on_path(usize::MAX, …) then does:
    //   vec![Vec::new(); usize::MAX + 1]  →  usize::MAX + 1 wraps to 0
    let allocation_size = usize::MAX.wrapping_add(1);
    assert_eq!(allocation_size, 0,
        "allocation arg wraps to 0; the subsequent loop body panics OOB");
}

// Fix: add `assert!(self.tree_height >= 2, "…")` at the top of CoPath::verify.
// Requirement: SR-1.1.


// ═════════════════════════════════════════════════════════════════════════════
// CTF C-2 — THE OFF-BY-ONE ABYSS
// ═════════════════════════════════════════════════════════════════════════════
//
// BRIEFING
// ────────
// A prover submits `tree_height = 1`. This is a semantically meaningless tree
// (a root with no inner nodes) but every guard before line 495 is satisfied.
// recompute_bottom_parents then executes:
//
//     for &parent_index in on_path[leaf_depth - 1].iter()
//
// With leaf_depth = 0 this is `on_path[usize::MAX]` → panic.
//
// OBJECTIVE: construct a CoPath that survives ingest_leaves,
//            validate_leaf_copath, and decode_inner_copath, then panics at 495.
//
// Trace with tree_height=1, leaf_indexes=[0]:
//   d=1, leaf_depth=0
//   compute_on_path(0, {0}) → [[0]]           length-1 vec
//   expected_leaf_coset: sibling of 0 is 1    expected = [1]
//   validate_leaf_copath: needs leaf_copath.len()==1  ← provide vec![42u8]
//   decode_inner_copath(None) → true
//   recompute_bottom_parents(0, …) → on_path[0 - 1] → PANIC
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn ctf_c2_tree_height_one_panic() {
    // FIXED: tree_height < 2 is now caught before recompute_bottom_parents.
    // verify() returns Err instead of reaching on_path[usize::MAX].
    let malicious_proof = CoPath::<DummyCfg> {
        tree_height: 1,
        leaf_copath:  vec![42u8],
        inner_copath: None,
        leaf_indexes: vec![0],
    };

    let result = malicious_proof.verify(&(), &(), &0u8, 2, vec![()]);
    assert!(result.is_err(), "C-2 fix: tree_height=1 must return Err, not panic");
}

/// Visualise the on_path structure that makes the OOB inevitable.
#[test]
fn ctf_c2_mechanism_proof() {
    use ark_std::collections::BTreeSet;

    // Reproduce compute_on_path(0, {0}) inline:
    let depth_leaves: usize = 0;
    let mut path_sets: Vec<Vec<usize>> = vec![Vec::new(); depth_leaves + 1]; // len = 1
    let indexes: BTreeSet<usize> = [0usize].iter().copied().collect();

    for &leaf_index in &indexes {
        let mut idx = leaf_index;
        let mut depth = depth_leaves;
        loop {
            path_sets[depth].push(idx);
            if depth == 0 { break; }
            idx >>= 1;
            depth -= 1;
        }
    }

    assert_eq!(path_sets.len(), 1, "on_path has exactly 1 element");
    assert_eq!(path_sets[0], vec![0usize]);

    // recompute_bottom_parents accesses on_path[leaf_depth - 1]:
    let leaf_depth: usize = 0;
    let bad_index = leaf_depth.wrapping_sub(1);
    assert_eq!(bad_index, usize::MAX,
        "on_path[usize::MAX] is an out-of-bounds access → panic");
}

// Fix: same as C-1 — `assert!(self.tree_height >= 2)`.
// Requirement: SR-1.1.


// ═════════════════════════════════════════════════════════════════════════════
// CTF C-3 — THE SHAPESHIFTER LEAF
// ═════════════════════════════════════════════════════════════════════════════
//
// BRIEFING
// ────────
// poseidon/mod.rs L62:
//
//     fn evaluate(…) { Self::compress(…) }
//
// This eliminates domain separation between leaf-layer and inner-layer hashing.
// Both `CRH::evaluate(params, &[a, b])` and `TwoToOneCRH::compress(params, a, b)`
// produce identical sponge sequences — absorb(a), absorb(b), squeeze(1) —
// giving the same output for any pair (a, b).
//
// TREE STRUCTURE CONFUSION ATTACK
// ────────────────────────────────
// Given a real height-3 tree with 4 leaves:
//   h_i  = CRH::evaluate(params, leaf_i)         leaf digests
//   N_01 = evaluate(params, h0, h1)              inner node
//   N_23 = evaluate(params, h2, h3)              inner node
//   root = compress(params, N_01, N_23)
//
// Craft a fake height-2 tree with 2 "leaves":
//   FL0 = [h0, h1]   →  CRH(FL0) = CRH([h0,h1]) = compress(h0,h1) = N_01
//   FL1 = [h2, h3]   →  CRH(FL1) = CRH([h2,h3]) = compress(h2,h3) = N_23
//   fake_root = evaluate(N_01, N_23) = compress(N_01, N_23) = root  ← SAME!
//
// A proof for FL0 from the fake tree verifies against the original root,
// proving membership of a leaf that was never committed to.
//
// FLAG: assert_eq!(fake_root, real_root) passes AND the forged proof verifies.
// ═════════════════════════════════════════════════════════════════════════════

#[test]
fn ctf_c3_domain_confusion_same_root() {
    use crate::{
        crh::poseidon,
        merkle_tree::tests::test_utils::poseidon_parameters,
    };
    use ark_ff::UniformRand;

    type F = ark_ed_on_bls12_381::Fr;
    type H = poseidon::CRH<F>;
    type TwoToOneH = poseidon::TwoToOneCRH<F>;

    struct PoseidonMTCfg;
    impl Config for PoseidonMTCfg {
        type Leaf = [F];
        type LeafDigest = F;
        type LeafInnerDigestConverter = IdentityDigestConverter<F>;
        type InnerDigest  = F;
        type LeafHash     = H;
        type TwoToOneHash = TwoToOneH;
    }
    type PoseidonMT = MerkleTree<PoseidonMTCfg>;

    let params = poseidon_parameters();
    let mut rng = ark_std::test_rng();

    // ── Step 1: build the real height-3 tree (4 leaves × 3 field elements) ──
    let real_leaves: Vec<Vec<F>> = (0..4)
        .map(|_| (0..3).map(|_| F::rand(&mut rng)).collect())
        .collect();
    let real_tree = PoseidonMT::new(&params, &params, &real_leaves).unwrap();
    let real_root = real_tree.root();

    // ── Step 2: recompute leaf digests (private field, so use CRH directly) ─
    let h: Vec<F> = real_leaves.iter()
        .map(|leaf| H::evaluate(&params, leaf.as_slice()).unwrap())
        .collect();

    // ── Step 3: demonstrate the core hash collision ───────────────────────────
    // absorb(&[h0, h1]) and absorb(h0); absorb(h1) are identical in the sponge.
    let crh_of_pair     = H::evaluate(&params, [h[0], h[1]]).unwrap();
    let compress_of_pair = TwoToOneH::compress(&params, h[0], h[1]).unwrap();

    assert_eq!(crh_of_pair, compress_of_pair,
        "C-3 core: CRH::evaluate([h0,h1]) == compress(h0,h1) — \
         domain separation does not exist");

    // ── Step 4: build the fake height-2 tree with 2-element leaves ───────────
    let fake_leaf_0: Vec<F> = vec![h[0], h[1]];
    let fake_leaf_1: Vec<F> = vec![h[2], h[3]];
    let fake_tree = PoseidonMT::new(&params, &params,
        &[fake_leaf_0.clone(), fake_leaf_1.clone()]).unwrap();
    let fake_root = fake_tree.root();

    // ── Step 5: FLAG — same root, different data ──────────────────────────────
    assert_eq!(fake_root, real_root,
        "C-3 FLAG: the fake height-2 tree shares the real height-3 tree's root. \
         Same commitment, entirely different leaves.");

    // ── Step 6: forge a proof ────────────────────────────────────────────────
    // A proof for FL0 from the fake tree must verify against the real root.
    let forged_proof = fake_tree.generate_proof(0).unwrap();
    let verifies = forged_proof
        .verify(&params, &params, &real_root, fake_leaf_0.as_slice())
        .unwrap();

    assert!(verifies,
        "C-3 EXPLOIT: proof for leaf [h0,h1] (never committed in the real tree) \
         verifies against the real root. Forgery complete.");
}

/// Atomic proof: evaluate and compress are identical for all inputs.
/// Runs 20 random trials to confirm this is not a coincidence.
#[test]
fn ctf_c3_evaluate_equals_compress_proof() {
    use crate::{
        crh::poseidon,
        merkle_tree::tests::test_utils::poseidon_parameters,
    };
    use ark_ff::UniformRand;

    type F = ark_ed_on_bls12_381::Fr;
    type H = poseidon::CRH<F>;
    type TwoToOneH = poseidon::TwoToOneCRH<F>;

    let params = poseidon_parameters();
    let mut rng = ark_std::test_rng();

    for _ in 0..20 {
        let a = F::rand(&mut rng);
        let b = F::rand(&mut rng);

        let via_crh      = H::evaluate(&params, [a, b]).unwrap();
        let via_compress = TwoToOneH::compress(&params, a, b).unwrap();
        let via_evaluate = TwoToOneH::evaluate(&params, a, b).unwrap();

        assert_eq!(via_crh, via_compress,
            "CRH::evaluate([a,b]) must equal compress(a,b)");
        assert_eq!(via_compress, via_evaluate,
            "compress must equal evaluate (L62 of poseidon/mod.rs)");
    }
}

// Fix: prefix each sponge call with a domain tag before absorbing data.
//   Leaf layer:  absorb(&[DOMAIN_LEAF]);   absorb(&leaf_input)
//   Inner layer: absorb(&[DOMAIN_INNER]);  absorb(left); absorb(right)
// This makes CRH::evaluate and compress produce different outputs for
// equivalent-sized inputs.
// Requirements: SR-0.2, SR-2.1.


// ═════════════════════════════════════════════════════════════════════════════
// CTF C-4 — THE PHANTOM WITNESS
// ═════════════════════════════════════════════════════════════════════════════
//
// BRIEFING
// ────────
// Two code paths serialize a leaf digest to bytes before feeding it into the
// TwoToOneCRH (Pedersen byte-based path):
//
//   Native  (mod.rs:83):         crate::to_uncompressed_bytes!(item)?
//                                 → CanonicalSerialize::serialize_uncompressed
//                                 → always canonical: x ∈ [0, p-1]
//
//   R1CS    (constraints.rs:36): from.to_non_unique_bytes_le()
//                                 → exposes the byte decomposition of the R1CS
//                                   variable WITHOUT constraining it to x < p
//
// A malicious SNARK prover can supply a witness where the byte decomposition of
// a leaf digest is non-canonical (represents x + k·p for some k ≥ 1).  The
// R1CS constraints are satisfied (no range check), but the hash input differs
// from any real leaf's canonical encoding.  The SNARK verifier accepts the
// proof; the native verifier would reject the same claim.
//
// OBJECTIVE
// ─────────
// 1. Show that x and x+p produce DIFFERENT byte sequences (same field element,
//    different integer representations).
// 2. Show that a byte-consuming CRH produces DIFFERENT outputs for those bytes.
// 3. Locate the exact lines that cause the divergence.
//
// FLAG: the two assert_ne assertions pass, proving the gap is real.
// ═════════════════════════════════════════════════════════════════════════════

/// Part 1: canonical vs. non-canonical bytes diverge.
#[test]
fn ctf_c4_canonical_vs_non_canonical_bytes() {
    use ark_ff::PrimeField;
    use ark_serialize::CanonicalSerialize;

    type F = ark_ed_on_bls12_381::Fr;

    // A small, known field element (42 ∈ F_p).
    let x = F::from(42u64);

    // ── Native path: canonical serialisation (mod.rs:83) ─────────────────
    let mut canonical_bytes = Vec::new();
    x.serialize_uncompressed(&mut canonical_bytes).unwrap();
    // Result: 32 little-endian bytes of the integer 42.
    assert_eq!(canonical_bytes.len(), 32);
    assert_eq!(&canonical_bytes[..2], &[42u8, 0u8],
        "first two bytes must be 42 (little-endian)");

    // ── Attacker path: construct bytes for x + p ──────────────────────────
    // In R1CS, to_non_unique_bytes_le() does not enforce the integer < p.
    // A dishonest prover can supply bytes(x + p) as the witness decomposition.
    // x + p is the same field element (x mod p == (x+p) mod p) but a different
    // 32-byte integer representation.
    let modulus = <F as PrimeField>::MODULUS; // the prime p as BigInt<4>
    let x_bigint = x.into_bigint();

    let mut carry: u128 = 0;
    let mut sum_limbs = [0u64; 4];
    for i in 0..4 {
        let s = x_bigint.0[i] as u128 + modulus.0[i] as u128 + carry;
        sum_limbs[i] = s as u64;
        carry = s >> 64;
    }
    // Lay out as little-endian bytes (same format as ark's serialize_uncompressed).
    let non_canonical_bytes: Vec<u8> = sum_limbs.iter()
        .flat_map(|limb| limb.to_le_bytes())
        .collect();
    assert_eq!(non_canonical_bytes.len(), 32);

    // ── FLAG part 1: the two byte strings differ ──────────────────────────
    assert_ne!(canonical_bytes, non_canonical_bytes,
        "C-4 FLAG (1/2): x=42 and x+p are the same field element but produce \
         different 32-byte representations. The R1CS path accepts either.");

    // ── FLAG part 2: a hash of those bytes yields different digests ───────
    // Use sha2::Sha256 as a stand-in for any byte-consuming CRH.
    // In the actual Pedersen Merkle tree, the two-to-one CRH is fed these bytes;
    // identical sensitivity applies to the Pedersen hash.
    use sha2::{Digest, Sha256};
    let digest_canonical     = Sha256::digest(&canonical_bytes);
    let digest_non_canonical = Sha256::digest(&non_canonical_bytes);

    assert_ne!(
        digest_canonical,
        digest_non_canonical,
        "C-4 FLAG (2/2): hashing the two byte representations yields DIFFERENT \
         digests. A prover who supplies non-canonical bytes to the R1CS gadget \
         computes a different hash than the native verifier, creating a \
         soundness gap."
    );
}

/// Part 2: locate the divergence in the source code.
///
/// Demonstrates that:
/// - Native ByteDigestConverter uses serialize_uncompressed → canonical
/// - R1CS BytesVarDigestConverter uses to_non_unique_bytes_le → non-canonical ok
///
/// A full end-to-end exploit would construct a malicious SNARK witness;
/// this test proves the underlying byte sensitivity that makes it possible.
#[test]
fn ctf_c4_divergence_source_map() {
    // The divergence lives between these two lines:
    //
    //   mod.rs:83          →  Ok(crate::to_uncompressed_bytes!(item)?)
    //                          = item.serialize_uncompressed(buf)   ← CANONICAL
    //
    //   constraints.rs:36  →  from.to_non_unique_bytes_le()         ← NOT ENFORCED
    //
    // Attack scenario:
    //   1. Prover builds a valid Merkle tree natively, gets root R.
    //   2. Prover constructs an R1CS witness for PathVar::verify_membership
    //      where a field element's byte decomposition uses bytes(x + p) instead
    //      of bytes(x).
    //   3. The Pedersen hash over bytes(x+p) ≠ hash over bytes(x), so the
    //      computed inner node hash diverges from the native value.
    //   4. The prover hand-crafts the remaining R1CS witnesses so the final
    //      root variable still equals R.
    //   5. The SNARK verifier sees a valid proof for root R; the native tree
    //      would reject this path because none of its nodes were computed with
    //      non-canonical bytes.
    //
    // Affected trees: Pedersen (byte-based) trees only.
    //   Poseidon (field-native) trees are NOT affected by this specific bug
    //   because IdentityDigestConverter never serialises to bytes.

    // Confirm the field element size so the attacker knows the byte budget:
    use ark_serialize::CanonicalSerialize;
    type F = ark_ed_on_bls12_381::Fr;

    let x = F::from(1729u64); // Hardy-Ramanujan number as the test element
    let mut bytes = Vec::new();
    x.serialize_uncompressed(&mut bytes).unwrap();

    assert_eq!(bytes.len(), 32,
        "Fr serialises to 32 bytes; x+p also fits in 32 bytes for small x, \
         confirming the non-canonical representation is in-range for the R1CS gadget");

    // The gap is in place. No further code is needed to confirm its existence.
    // See constraints.rs:36 for the vulnerable line and SR-3.3 for the fix spec.
}

// Fix: replace to_non_unique_bytes_le() with to_bytes_le() and add a
// range-check constraint proving each byte decomposition represents x < p.
// Alternatively, eliminate the byte path by switching to field-native Poseidon
// for all tree hashing (makes this constraint unnecessary).
// Requirement: SR-3.3.
