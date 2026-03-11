# Security Requirements Specification
## Arkworks Merkle Tree Library

Version: 1.0
Date: 2026-03-08
Scope: `crypto-primitives/src/merkle_tree/` and trait-level contracts in `crh/`

---

## Threat Model

**Attacker capability**: Controls the serialized proof bytes (`Path`, `CoPath`) delivered
to a verifier. Can choose arbitrary field values for every `pub` field in proof structs.
Cannot break collision resistance of the underlying hash function.

**Assets protected**: (1) Soundness — no false inclusion proof accepted;
(2) Availability — no input causes panic, OOM, or unbounded computation in the verifier.

---

## Hit-Path Analysis (attack surface enumeration)

### CRITICAL

| ID | Hit Path | Location | Mechanism | Status |
|----|----------|----------|-----------|--------|
| C-1 | `tree_height` underflow | `CoPath::verify` L282-283 | Attacker sets `tree_height = 0`. `leaf_depth = d - 1` wraps to `usize::MAX`. `compute_on_path(usize::MAX, ...)` allocates `vec![Vec::new(); usize::MAX + 1]` → OOM/panic. | Done. |
| C-2 | `tree_height = 1` panic | `recompute_bottom_parents` L495 | `leaf_depth = 0`, then `on_path[leaf_depth - 1]` = `on_path[usize::MAX]` → index-out-of-bounds panic. | Done. |
| C-3 | No domain separation enforcement | `TwoToOneCRHScheme` trait | `evaluate()` and `compress()` are separate methods but nothing enforces they use distinct domains. Poseidon's `evaluate` calls `compress` directly (poseidon/mod.rs L62). An attacker who can choose leaves could craft a leaf whose digest equals an inner node hash, proving a non-existent leaf. | TODO now. |
| C-4 | Non-canonical bytes in R1CS | `BytesVarDigestConverter` constraints.rs L37 | `to_non_unique_bytes_le()` permits multiple byte representations of the same field element. The native Merkle tree uses `to_uncompressed_bytes!` (canonical). A malicious prover can exploit this divergence to satisfy R1CS constraints with a witness that doesn't match the native computation. | Later. |

### HIGH

| ID | Hit Path | Location | Mechanism | Status |
|----|----------|----------|-----------|--------|
| H-1 | Vacuous empty-proof acceptance | `CoPath::verify` L278-280 | `leaf_indexes = []` returns `Ok(true)` against ANY root. A consumer that doesn't independently verify the proof covers the expected indices accepts a no-op proof. | Done. |
| H-2 | `tree_height` not bound to root | `CoPath::verify` L282 | The verifier uses the prover-supplied `tree_height` with no check against the expected height for the given root. An attacker could craft a proof for a different-height tree that (under hash collision) verifies against the same root. Even without collision, the API is misleading. | Done. |
| H-3 | `leaf_indexes` not range-checked | `CoPath::verify` L291 | No check that every `leaf_index < 2^(tree_height-1)`. Out-of-range indices feed into `compute_on_path` producing phantom on-path entries. Verification still fails at root check (no soundness break), but enables confusion attacks and wasted verifier work. | Later. |
| H-4 | All proof struct fields `pub` | `CoPath`, `Path` structs | Every field is `pub`. Deserialised proofs can have any combination of values. No constructor-level invariant enforcement exists. Consumers must rely entirely on `verify()` to reject invalid proofs. | Later. |
| H-5 | `Path::verify` unbounded `leaf_index` | `Path::verify` L200 | `leaf_index` is used modulo the effective tree size via bit-shifting. Index `2^60 + 3` and index `3` behave identically for a height-4 tree. No range check rejects semantically invalid indices. | TODO now. |

### MEDIUM

| ID | Hit Path | Location | Mechanism | Status |
|----|----------|----------|-----------|--------|
| M-1 | Duplicate `leaf_indexes` silent overwrite | `ingest_leaves` L444 | `BTreeMap::insert` overwrites. If `leaf_indexes = [3, 3]` with two different leaves provided, the second leaf's hash replaces the first silently. The iterator consumes both. Verification proceeds using only the second hash. | Later. |
| M-2 | Duplicate coordinates in inner copath | `decode_inner_copath` L588 | Monotonic check uses `<` not `<=`. Equal coordinates `(d,i) == (d,i)` are accepted if digests match. Allows proof bloat: attacker pads redundant entries, inflating verifier memory and time. | TODO now. |
| M-3 | No inner-copath index upper bound | `push_entry` closure L583 | Depth is bounded (`1..tree_height`), but the index at each depth is unbounded. An entry at `(depth=1, index=10^18)` is accepted and inserted into the BTreeMap. Orphan entries waste memory but don't affect soundness. | TODO now. |
| M-4 | `set_leaf_position` silent truncate/pad | `PathVar::set_leaf_position` constraints.rs L159-164 | If the provided boolean vector is shorter than `auth_path.len()`, it is padded with `false`. If longer, truncated. Neither case produces an error. Can mask verifier-side bugs in R1CS circuits. | Later. |
| M-5 | `check_update` accepts without validation | `MerkleTree::check_update` L710 | Asserts `index < leaf_nodes.len()` (panics on invalid), but on failure of the root check, the tree is unmodified — correct behavior. However, the method takes `T: Borrow<P::Leaf>` as generic param but doesn't use it, suggesting a stale signature. | Later. |

### LOW

| ID | Hit Path | Location | Mechanism | Status |
|----|----------|----------|-----------|--------|
| L-1 | `Default` as security-relevant sentinel | `MerkleTree::blank` L717 | `InnerDigest::default()` and `LeafDigest::default()` populate blank trees. Any leaf that hashes to the default value is indistinguishable from an empty slot. No explicit documentation warns implementors about this. | Later. |
| L-2 | Hash LUT keyed by heap index | `CoPath::verify` LUT usage | LUT keys are heap-position integers. If two logically distinct positions map to the same heap index (impossible in a correct implementation, but possible if `level_index` is called with wrong depth/pos), cached values would collide silently. | Later. |
| L-3 | No proof-of-non-membership | API level | The API only proves inclusion. Consumers expecting exclusion proofs from the same structure must build their own non-membership logic. | Later. |

---

## Security Requirements

Requirements are structured as a dependency DAG. Each requirement has a unique ID,
a tier (MUST/SHOULD/MAY), the hit paths it mitigates, and its dependencies.

### Tier 0: Foundational (no dependencies)

```
SR-0.1  [MUST]  [mitigates: C-3]
  Title: Domain-separated hashing
  Requirement: For any Config implementation used in production,
    TwoToOneHash::evaluate() and TwoToOneHash::compress() MUST use
    distinct domain tags (e.g., different initial sponge state, prefix
    byte, or capacity element) such that evaluate(a, b) != compress(a, b)
    for all inputs (a, b).
  Verification: Unit test that evaluates the same (left, right) pair via
    both methods and asserts inequality.

SR-0.2  [MUST]  [mitigates: C-1, C-2]
  Title: tree_height input validation
  Requirement: CoPath::verify() MUST reject any proof where
    tree_height < 2 before performing any computation. Return Ok(false)
    or Err, never panic or allocate.
  Verification: Test with tree_height = 0 and tree_height = 1 with
    non-empty leaf_indexes; assert no panic and Ok(false).

SR-0.3  [MUST]  [mitigates: C-4]
  Title: Canonical byte conversion in R1CS
  Requirement: BytesVarDigestConverter MUST produce byte representations
    that are bit-for-bit identical to the native ByteDigestConverter for
    all valid field elements. Replace to_non_unique_bytes_le() with
    to_bytes_le() or add canonical-enforcement constraints.
  Verification: Constraint satisfaction test where the native and R1CS
    roots are compared for 100 random trees.
```

### Tier 1: Input Validation (depends on Tier 0)

```
SR-1.1  [MUST]  [mitigates: H-2]  [depends: SR-0.2]
  Title: Verifier-supplied tree height
  Requirement: CoPath::verify() MUST accept an expected_tree_height
    parameter (or the verify API must be changed so tree_height is not
    prover-controlled). Reject if self.tree_height != expected_tree_height.
  Verification: Test that a valid proof with altered tree_height is rejected.

SR-1.2  [MUST]  [mitigates: H-3, H-5]  [depends: SR-0.2]
  Title: Leaf index range check
  Requirement: Both Path::verify() and CoPath::verify() MUST reject any
    leaf_index >= 2^(tree_height - 1). For CoPath, this check applies to
    every element of self.leaf_indexes.
  Verification: Test with leaf_index = 2^(tree_height-1) (one past the end);
    assert Ok(false).

SR-1.3  [SHOULD]  [mitigates: M-1]  [depends: SR-1.2]
  Title: Reject duplicate leaf indexes
  Requirement: CoPath::verify() SHOULD reject proofs where leaf_indexes
    contains duplicate values. Either return Ok(false) or Err.
  Verification: Test with leaf_indexes = [3, 3] and appropriate leaves;
    assert rejection.

SR-1.4  [SHOULD]  [mitigates: M-3]  [depends: SR-0.2]
  Title: Inner copath index bounds
  Requirement: decode_inner_copath SHOULD reject any entry whose index
    exceeds the maximum valid node index at that depth:
    index < 2^depth.
  Verification: Test with inner copath entry at (depth=1, index=2);
    assert rejection (depth 1 has only indices 0 and 1).
```

### Tier 2: Structural Integrity (depends on Tier 1)

```
SR-2.1  [MUST]  [mitigates: H-1]  [depends: SR-1.1]
  Title: Document or prevent vacuous acceptance
  Requirement: Either (a) CoPath::verify() MUST return Ok(false) for
    empty leaf_indexes, or (b) the API documentation MUST explicitly state
    that empty proofs are vacuously true and consumers MUST check
    proof.leaf_indexes.len() > 0 before trusting the result.
  Verification: If option (a): test empty proof returns false.
    If option (b): doc-test demonstrating the consumer check.

SR-2.2  [SHOULD]  [mitigates: M-2]  [depends: SR-1.4]
  Title: Strict monotonic inner copath ordering
  Requirement: decode_inner_copath SHOULD enforce strict monotonic
    ordering: (depth, index) must be strictly greater than the previous
    entry. Change the check from `<` to `<=` at the comparison.
  Verification: Test with duplicate coordinate (same depth, same index,
    same digest); assert rejection.

SR-2.3  [SHOULD]  [mitigates: H-4]  [depends: SR-1.2, SR-1.3]
  Title: Proof struct invariant enforcement
  Requirement: CoPath and Path SHOULD expose only opaque constructors.
    Fields should be pub(crate) or private, with proof objects created
    only via generate_proof / generate_multi_proof or a validated
    deserialization path.
  Verification: Compile-time: external crate cannot set fields directly.
    Runtime: deserialised proof is validated before verify() is callable,
    or verify() performs all validation internally.
```

### Tier 3: Defence in Depth (depends on Tier 2)

```
SR-3.1  [SHOULD]  [mitigates: L-1]
  Title: Document Default digest semantics
  Requirement: The Config trait documentation SHOULD explicitly warn that
    LeafDigest::default() and InnerDigest::default() serve as the
    "empty" sentinel. Implementations SHOULD ensure that no legitimate
    leaf hashes to the default digest under normal operation.
  Verification: Documentation review. Optional: test that hash(random_leaf)
    != default for 1000 random leaves.

SR-3.2  [SHOULD]  [mitigates: M-4]  [depends: SR-0.3]
  Title: set_leaf_position length validation
  Requirement: PathVar::set_leaf_position SHOULD return an error (or at
    minimum a debug_assert) if the provided boolean vector length does not
    equal auth_path.len() + 1. Silent padding and truncation mask bugs.
  Verification: Test that mismatched-length input triggers the error.

SR-3.3  [MAY]  [mitigates: C-3]  [depends: SR-0.1]
  Title: Trait-level domain separation marker
  Requirement: The Config trait MAY include an associated constant or
    type-level marker (e.g., const DOMAIN_SEPARATION: bool = true) that
    concrete implementations must set, making the domain separation
    requirement visible at the type level rather than relying on
    documentation alone.
  Verification: Compile-time: Config implementations that don't set the
    marker produce a warning or fail to compile.

SR-3.4  [MAY]  [mitigates: L-2]
  Title: LUT key collision assertion
  Requirement: In debug builds, the hash LUT insertion MAY assert that
    any existing entry at a key matches the value being inserted, to
    catch internal logic errors during development.
  Verification: Debug-mode test with intentionally conflicting insertions
    triggers assertion.
```

---

## Dependency Graph

```
             SR-0.1   SR-0.2   SR-0.3
               |        |        |
               |    +----+----+  |
               |    |    |    |  |
               v    v    v    v  v
             SR-3.3 SR-1.1 SR-1.2 SR-1.3  SR-3.2
                      |      |      |
                      v      v      v
                    SR-2.1  SR-2.3
                             |
                    SR-1.4   |
                      |      |
                      v      |
                    SR-2.2   |
                             v
                          SR-3.1, SR-3.4
```

Implement Tier 0 first (blocks all downstream work).
Tier 1 can be parallelised after Tier 0.
Tier 2 and 3 are incremental hardening.

---

## Test Coverage Matrix

| Requirement | Positive Test | Negative Test | Property Test |
|-------------|--------------|---------------|---------------|
| SR-0.1 | evaluate != compress for random inputs | — | proptest: forall (l,r), evaluate(l,r) != compress(l,r) |
| SR-0.2 | tree_height=2 verifies normally | tree_height=0, tree_height=1 no panic | — |
| SR-0.3 | R1CS root == native root for 100 trees | witness with non-canonical bytes fails | — |
| SR-1.1 | proof with correct height verifies | proof with wrong height rejected | — |
| SR-1.2 | max valid index verifies | index = 2^(h-1) rejected | proptest: random OOB index rejected |
| SR-1.3 | deduplicated indexes verify | [3,3] rejected | — |
| SR-1.4 | valid inner coords accepted | index >= 2^depth rejected | proptest: random OOB coord rejected |
| SR-2.1 | non-empty proof verifies | empty proof returns false (opt a) | — |
| SR-2.2 | strictly increasing coords accepted | duplicate coord rejected | — |
| SR-2.3 | proof from generate_* verifies | manually constructed proof with bad fields rejected | — |
| SR-3.1 | — | hash(random) != default for 1000 leaves | — |
| SR-3.2 | correct-length position accepted | wrong-length position errors | — |
| SR-3.3 | Config with marker compiles | Config without marker warns | — |
| SR-3.4 | consistent LUT insertions pass | conflicting insertion asserts in debug | — |
