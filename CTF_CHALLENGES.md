# Arkworks Merkle Tree — CTF Challenges

Four capture-the-flag challenges, each derived from a critical finding in
[SECURITY_REQUIREMENTS.md](SECURITY_REQUIREMENTS.md). The challenges are
self-contained, ordered by conceptual difficulty, and have runnable Rust
exploit tests in:

```
crypto-primitives/src/merkle_tree/tests/ctf_challenges.rs
```

Run all challenges:
```bash
cargo test --package ark-crypto-primitives --features merkle_tree ctf
```

---

## C-1 · The Infinite Allocator  ★☆☆☆

**Points:** 100
**Category:** Denial-of-Service / Memory Safety
**File:** `src/merkle_tree/mod.rs`, line 283
**Requirement violated:** SR-1.1

### Briefing

A remote prover serialises and submits a `CoPath` batch proof. Your node
deserialises it and calls `CoPath::verify`. If you can make that call crash
the verifier process with a single proof, you win.

### Vulnerable code

```rust
// mod.rs L278-283
if self.leaf_indexes.is_empty() {
    return Ok(true)           // ← safe path for empty batch
}
let d = self.tree_height;
let leaf_depth = d - 1;       // ← BUG: no bounds check, d=0 underflows
```

### Objective

Construct a `CoPath<P>` with the minimum number of fields set such that
`verify(…)` panics before returning.

### Hints

1. What happens to `0usize - 1` in Rust debug mode?
2. What happens in release mode?
3. Which field in `CoPath` bypasses the `is_empty()` guard?
4. The exploit is five lines of Rust.

### Flag

The test `ctf_c1_tree_height_zero_dos` is marked `#[should_panic]`. If it
passes, you found the flag. Run `ctf_c1_mechanism_proof` to see the exact
arithmetic without crashing.

### Fix

```rust
// Add at the top of CoPath::verify, after the is_empty check:
if self.tree_height < 2 {
    return Err(crate::Error::GenericError("tree_height must be >= 2".into()));
}
```

---

## C-2 · The Off-By-One Abyss  ★★☆☆

**Points:** 150
**Category:** Denial-of-Service / Index Out-of-Bounds
**File:** `src/merkle_tree/mod.rs`, line 495
**Requirement violated:** SR-1.1

### Briefing

Same threat model as C-1, but the guard `tree_height >= 2` has been added
(imagine C-1 was patched). Can you still crash the verifier?

### Vulnerable code

```rust
// mod.rs L495  (inside recompute_bottom_parents)
for &parent_index in on_path[leaf_depth - 1].iter() {
//                             ─────────────
// leaf_depth = tree_height - 1
// If tree_height = 1 → leaf_depth = 0 → 0 - 1 underflows
```

### Objective

Craft a `CoPath<P>` with `tree_height = 1` that:
1. Passes `ingest_leaves` (provide the right number of leaves).
2. Passes `validate_leaf_copath` (provide the correct number of sibling digests).
3. Passes `decode_inner_copath` (no inner copath needed).
4. Panics at line 495.

### Hints

1. `compute_on_path(0, {0})` returns a vec of length 1. What index does
   `recompute_bottom_parents` access?
2. How many sibling digests does a 1-leaf proof at `leaf_indexes=[0]` require?
3. Draw the "tree" of height 1. It has a root and two leaves. What does
   `expected_leaf_coset` return for on-path node index 0?

### Flag

Test `ctf_c2_tree_height_one_panic` passes. Run `ctf_c2_mechanism_proof` to
observe the `on_path` vector that makes the OOB inevitable.

### Fix

Same as C-1: `tree_height >= 2` check. A minimum height of 2 rules out both
C-1 (height=0) and C-2 (height=1) simultaneously.

---

## C-3 · The Shapeshifter Leaf  ★★★☆

**Points:** 300
**Category:** Cryptographic Forgery / Domain Separation
**File:** `src/crh/poseidon/mod.rs`, line 62
**Requirement violated:** SR-0.2, SR-2.1

### Briefing

You are not the prover of a tree you control — you are an observer who has
seen a valid Merkle root `R` for a 4-leaf Poseidon tree. You want to convince
a verifier that a leaf of your choosing belongs to this tree, even though it
was never committed to. No knowledge of any secret key is required.

The existing code even acknowledges this class of attack (mod.rs L689):

> "if the leaf hash and two-to-one hash uses same underlying CRH, a malicious
> prover can prove a leaf while the actual node is an inner node"

### Vulnerable code

```rust
// poseidon/mod.rs L57-63
fn evaluate<T: Borrow<Self::Input>>(
    parameters: &Self::Parameters,
    left_input: T,
    right_input: T,
) -> Result<Self::Output, Error> {
    Self::compress(parameters, left_input, right_input)  // ← no domain tag
}
```

And the sponge absorb sequences are:

```
CRH::evaluate(params, &[a, b]):          sponge ← absorb([a, b]) → squeeze(1)
TwoToOneCRH::compress(params, a, b):     sponge ← absorb(a) → absorb(b) → squeeze(1)
```

Both sequences feed `a` then `b` into the same sponge state → **identical output**.

### Objective

1. Build a real height-3 Poseidon tree with 4 random 3-element leaves.
2. Compute the four leaf digests `h0, h1, h2, h3`.
3. Construct a **fake** height-2 tree whose leaves are `[h0, h1]` and `[h2, h3]`.
4. Show `fake_root == real_root`.
5. Generate a proof from the fake tree for its leaf 0 and verify it against `real_root`.

### Hints

1. A height-3 tree has `compress(compress(h0,h1), compress(h2,h3))` as root.
2. A fake leaf `[h0, h1]` hashes to `CRH::evaluate(params, &[h0, h1])`. What
   does that equal by the bug above?
3. The fake height-2 tree's root is `compress(CRH(FL0), CRH(FL1))`. Expand this.
4. `MerkleTree::new` stores leaf digests but does not expose them. Use
   `CRH::evaluate` directly to recompute them.

### Flag

Both assertions in `ctf_c3_domain_confusion_same_root` pass:

```
assert_eq!(fake_root, real_root,  "same commitment, different data");
assert!(verifies,                  "forged proof accepted");
```

### Fix

Add a domain separation prefix to each sponge before absorbing data:

```rust
const DOMAIN_LEAF:  u8 = 0x00;
const DOMAIN_INNER: u8 = 0x01;

// In CRH::evaluate (leaf layer):
sponge.absorb(&[DOMAIN_LEAF]);
sponge.absorb(&input);

// In TwoToOneCRH::compress (inner layer):
sponge.absorb(&[DOMAIN_INNER]);
sponge.absorb(left_input);
sponge.absorb(right_input);
```

---

## C-4 · The Phantom Witness  ★★★★

**Points:** 500
**Category:** R1CS Soundness / Canonical Serialisation
**File:** `src/merkle_tree/constraints.rs`, line 36
**Requirement violated:** SR-3.3

### Briefing

You are a malicious SNARK prover in a zero-knowledge proof system that uses
the Pedersen Merkle tree for membership proofs. The verifier checks a Groth16
(or similar) proof that you know a leaf in the tree. Can you convince the
verifier of a membership claim that is false?

### The divergence

Two code paths convert a leaf digest to bytes before feeding it to the
Pedersen two-to-one hash:

| Path | Code | Canonical? |
|------|------|-----------|
| Native `ByteDigestConverter` (mod.rs:83) | `crate::to_uncompressed_bytes!(item)?` → `serialize_uncompressed` | ✅ Always |
| R1CS `BytesVarDigestConverter` (constraints.rs:36) | `from.to_non_unique_bytes_le()` | ❌ Not enforced |

`to_non_unique_bytes_le()` returns the byte decomposition of an R1CS
variable **without constraining it to be less than `p`**. A well-formed
prover produces canonical bytes, but the constraint system accepts any
decomposition whose bits sum to a consistent field element.

### Attack scenario

```
1. Build a valid tree natively. Root = R.
2. In the R1CS witness, set the byte decomposition of a leaf digest
   to bytes(x + p) instead of bytes(x).
   (Same field element, different 32-byte integer.)
3. The Pedersen hash over bytes(x+p) ≠ hash over bytes(x).
4. Hand-craft the remaining witness so the final computed root = R.
5. The SNARK verifier sees: valid proof, root = R.
   The native verifier would reject: no real leaf hashes this way.
```

### Objective

1. Take a field element `x` (e.g. `F::from(42u64)`).
2. Compute its canonical byte serialisation via `serialize_uncompressed`.
3. Manually compute bytes of `x + p` using the BigInt representation.
4. Show the two byte arrays differ (`assert_ne`).
5. Show that a byte-consuming hash (Sha256 as a stand-in) produces different
   digests for the two inputs.

### Hints

1. `<F as PrimeField>::MODULUS` gives the prime `p` as `BigInt<4>`.
2. `x.into_bigint()` gives `x`'s integer representation.
3. Adding two `BigInt<4>` values manually: sum limbs with carry.
4. `sha2::Digest::digest(&bytes)` hashes a byte slice (sha2 is a dependency).

### Flag

Both `assert_ne` assertions in `ctf_c4_canonical_vs_non_canonical_bytes` pass.

### Fix

Replace `to_non_unique_bytes_le()` with a constrained version that enforces
the byte decomposition is in canonical range:

```rust
// Option A: add a range-check constraint (bytes represent integer < p)
let bytes = from.to_bytes_le()?;
enforce_range_check(&bytes, p)?;   // additional R1CS constraint

// Option B (preferred): eliminate the byte path entirely.
// Switch the tree to field-native Poseidon for all hashing.
// Then BytesVarDigestConverter is never needed.
```

---

## Summary Table

| ID | Test function(s)                          | Expected outcome         |
|----|-------------------------------------------|--------------------------|
| C-1 | `ctf_c1_tree_height_zero_dos`            | `#[should_panic]` passes |
| C-1 | `ctf_c1_mechanism_proof`                 | explains underflow       |
| C-2 | `ctf_c2_tree_height_one_panic`           | `#[should_panic]` passes |
| C-2 | `ctf_c2_mechanism_proof`                 | explains OOB index       |
| C-3 | `ctf_c3_domain_confusion_same_root`      | both asserts pass        |
| C-3 | `ctf_c3_evaluate_equals_compress_proof`  | 20 random trials pass    |
| C-4 | `ctf_c4_canonical_vs_non_canonical_bytes`| both assert_ne pass      |
| C-4 | `ctf_c4_divergence_source_map`           | documents the gap        |

## Learning Objectives

After solving all four challenges, you should be able to:

- **C-1/C-2**: Identify missing input validation on length/height fields in
  cryptographic data structures and understand how attacker-controlled integers
  flow into arithmetic operations.

- **C-3**: Explain what domain separation means in hash-based proof systems,
  why absorbing the same field elements in the same order through the same
  sponge is insufficient as a separator, and how to craft a tree-structure
  confusion attack without breaking any hash function.

- **C-4**: Explain the difference between a constraint system *accepting* a
  witness and that witness being *sound* relative to a native computation,
  and identify where R1CS constraints fail to enforce canonical serialisation.
