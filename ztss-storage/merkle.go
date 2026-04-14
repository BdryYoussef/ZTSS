// merkle.go — Binary Merkle tree construction and integrity verification.
//
// ── Algorithm ─────────────────────────────────────────────────────────────────
//
// Leaf nodes:  L_i = SHA-256(chunk_i.Data)  = chunk_i.CID
//
// Internal nodes (bottom-up, pairwise):
//
//   If the current level has an odd number of nodes, the last node is
//   duplicated before pairing (standard Bitcoin/RFC Merkle convention).
//   This ensures the tree is always balanced and the root is well-defined
//   for any number of leaves ≥ 1.
//
//   parent(left, right) = SHA-256( left.bytes || right.bytes )
//
// Iteration continues until a single root hash remains.
//
// ── Single-leaf degenerate case ───────────────────────────────────────────────
//
//   For a file that fits in one chunk, MerkleRoot = SHA-256(chunk_0.Data)
//   (the leaf itself; no internal node is computed).
//
// ── Security property ─────────────────────────────────────────────────────────
//
//   Flipping any single byte in any chunk changes that chunk's CID, which
//   propagates through every ancestor up to the root.  VerifyIntegrity
//   therefore detects any single-byte mutation in any chunk (TS-02).
//
// Wiki references:
//   - [[storage_layer#Merkle DAG]]
//   - [[database_schema#MerkleRoot]]
//   - TF-04: VerifyIntegrity = true after reassembly
//   - TS-02: Modifying 1 byte → Merkle reject + alert log
package storage

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// MerkleRoot is the 32-byte SHA-256 root of the chunk Merkle tree.
// It serves as the globally unique file identifier ("root_cid") returned by
// POST /upload and is the primary handle for sharing, re-encryption, and audit.
//
// Encoding for the API layer: hex string (MerkleRoot.String()).
type MerkleRoot [32]byte

// String returns the root as a 64-character lowercase hex string.
func (r MerkleRoot) String() string {
	return fmt.Sprintf("%x", r[:])
}

// ── MerkleRootFromChunks ──────────────────────────────────────────────────────

// MerkleRootFromChunks computes the Merkle root from an ordered slice of Chunks.
//
// Preconditions:
//   - chunks must be in ascending Index order (ChunkFile guarantees this).
//   - len(chunks) >= 1.
//
// The function treats each chunk's CID as the corresponding leaf hash.
// It does NOT recompute CIDs from Data — callers must ensure chunk.CID is
// consistent with chunk.Data (VerifyIntegrity does this check independently).
func MerkleRootFromChunks(chunks []Chunk) (MerkleRoot, error) {
	if len(chunks) == 0 {
		return MerkleRoot{}, errors.New("ztss/storage: MerkleRootFromChunks: no chunks")
	}

	// Build the leaf level from CIDs.
	level := make([][32]byte, len(chunks))
	for i, c := range chunks {
		level[i] = c.CID
	}

	return computeRoot(level), nil
}

// MerkleRootFromHashes computes the Merkle root directly from an ordered slice
// of 32-byte hashes.  Used by VerifyIntegrity to recompute the root from
// freshly-hashed chunk data without constructing Chunk objects.
func MerkleRootFromHashes(hashes [][32]byte) (MerkleRoot, error) {
	if len(hashes) == 0 {
		return MerkleRoot{}, errors.New("ztss/storage: MerkleRootFromHashes: no hashes")
	}
	return computeRoot(hashes), nil
}

// ── VerifyIntegrity ───────────────────────────────────────────────────────────

// VerifyIntegrity recomputes the Merkle root from scratch — rehashing every
// chunk's Data and rebuilding the entire tree — and compares it against the
// expected root.
//
// Returns true iff:
//  1. Every chunk's recomputed SHA-256(Data) matches its stored CID.
//  2. The Merkle root built from all recomputed CIDs equals root.
//
// Any single-byte mutation in any chunk's Data will cascade through the tree
// and change the root, satisfying TF-04 and TS-02.
//
// Called after ReassembleFile and should be called by nodes before serving
// a chunk to a client.
//
// NOTE: chunks must be in ascending Index order; pass through sortedChunks
// if the caller cannot guarantee ordering.
func VerifyIntegrity(chunks []Chunk, root MerkleRoot) bool {
	if len(chunks) == 0 {
		return false
	}

	// Recompute every leaf CID from raw data.
	leaves := make([][32]byte, len(chunks))
	for i, c := range chunks {
		computed := sha256.Sum256(c.Data)
		if computed != c.CID {
			// Chunk CID is inconsistent with its data — fast-fail.
			return false
		}
		leaves[i] = computed
	}

	// Recompute the tree from the fresh leaves.
	got := computeRoot(leaves)
	return got == root
}

// ── Tree builder ──────────────────────────────────────────────────────────────

// computeRoot implements the bottom-up Merkle tree reduction.
//
// Invariant: each pass halves the number of nodes (rounding up).
// Termination: guaranteed because len(level) strictly decreases each iteration.
func computeRoot(level [][32]byte) MerkleRoot {
	// Single-leaf shortcut: the root IS the single leaf hash.
	if len(level) == 1 {
		return MerkleRoot(level[0])
	}

	for len(level) > 1 {
		level = pairwiseHash(level)
	}
	return MerkleRoot(level[0])
}

// pairwiseHash reduces a level by pairing adjacent nodes.
//
// If len(level) is odd, the last node is duplicated before pairing:
//
//	level = [A, B, C]  →  pairs = [(A,B), (C,C)]
//
// Each pair is hashed as SHA-256( left.bytes || right.bytes ).
// The returned slice has length ceil(len(level) / 2).
func pairwiseHash(level [][32]byte) [][32]byte {
	// Duplicate last element if odd number of nodes.
	if len(level)%2 != 0 {
		level = append(level, level[len(level)-1])
	}

	next := make([][32]byte, len(level)/2)
	for i := 0; i < len(level); i += 2 {
		h := sha256.New()
		h.Write(level[i][:])
		h.Write(level[i+1][:])
		copy(next[i/2][:], h.Sum(nil))
	}
	return next
}

// ── MerkleProof (audit / spot-check support) ──────────────────────────────────

// MerkleProof holds the sibling hashes needed to verify that a single chunk
// belongs to the tree identified by a given MerkleRoot.
//
// Used by nodes that want to prove possession of a specific chunk without
// revealing the full chunk tree (bandwidth-efficient integrity proof).
type MerkleProof struct {
	// LeafIndex is the zero-based position of the chunk being proven.
	LeafIndex uint64

	// Siblings are the sibling hashes at each tree level, ordered from the
	// leaf level up to (but not including) the root.
	// IsRight[i] is true when Siblings[i] is the right sibling (i.e., the
	// proven node is on the left at level i).
	Siblings [][32]byte
	IsRight  []bool
}

// GenerateMerkleProof produces a MerkleProof for the chunk at leafIndex.
// Returns an error if leafIndex is out of range.
//
// The proof allows a verifier to recompute the root from just:
//   - SHA-256(chunk.Data)   (the leaf)
//   - The sibling hashes in MerkleProof.Siblings
func GenerateMerkleProof(chunks []Chunk, leafIndex uint64) (MerkleProof, error) {
	if len(chunks) == 0 {
		return MerkleProof{}, errors.New("ztss/storage: GenerateMerkleProof: no chunks")
	}
	if leafIndex >= uint64(len(chunks)) {
		return MerkleProof{}, fmt.Errorf(
			"ztss/storage: GenerateMerkleProof: leafIndex %d out of range [0, %d)",
			leafIndex, len(chunks),
		)
	}

	level := make([][32]byte, len(chunks))
	for i, c := range chunks {
		level[i] = c.CID
	}

	var siblings [][32]byte
	var isRight []bool
	idx := leafIndex

	for len(level) > 1 {
		// Duplicate last element if odd.
		if len(level)%2 != 0 {
			level = append(level, level[len(level)-1])
		}

		// Find our sibling.
		var sibIdx uint64
		if idx%2 == 0 {
			// We are the left node; sibling is to the right.
			sibIdx = idx + 1
			isRight = append(isRight, true)
		} else {
			// We are the right node; sibling is to the left.
			sibIdx = idx - 1
			isRight = append(isRight, false)
		}
		siblings = append(siblings, level[sibIdx])

		// Move up: compute next level and halve the index.
		level = pairwiseHash(level)
		idx /= 2
	}

	return MerkleProof{
		LeafIndex: leafIndex,
		Siblings:  siblings,
		IsRight:   isRight,
	}, nil
}

// VerifyMerkleProof checks that leafHash belongs to the tree rooted at root,
// using the provided MerkleProof.
//
// Recomputes the path from leaf to root using the sibling hashes and verifies
// the final result equals root.  Returns true iff the proof is valid.
func VerifyMerkleProof(leafHash [32]byte, proof MerkleProof, root MerkleRoot) bool {
	if len(proof.Siblings) != len(proof.IsRight) {
		return false
	}

	current := leafHash
	for i, sibling := range proof.Siblings {
		h := sha256.New()
		if proof.IsRight[i] {
			// Sibling is on the right; current is left.
			h.Write(current[:])
			h.Write(sibling[:])
		} else {
			// Sibling is on the left; current is right.
			h.Write(sibling[:])
			h.Write(current[:])
		}
		copy(current[:], h.Sum(nil))
	}

	return MerkleRoot(current) == root
}
