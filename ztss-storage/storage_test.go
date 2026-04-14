// storage_test.go — exhaustive test suite for the ztss-storage package.
//
// CDC test identifiers covered:
//   TF-01  chunk → reassemble → identical bytes (round-trip)
//   TF-03  Replicate: Has(cid)==true on ≥ k=3 nodes after upload
//   TF-04  VerifyIntegrity=true after reassembly (full pipeline)
//   TF-05  Fetch succeeds from peer when local is absent
//   TS-02  Modifying 1 byte → VerifyIntegrity=false + ReassembleFile error
//
// File structure:
//   Section 1  — ChunkFile (splitting, CID computation, boundaries)
//   Section 2  — VerifyIntegrity (tamper detection, TS-02)
//   Section 3  — ReassembleFile (round-trip TF-01, error paths)
//   Section 4  — Merkle tree (root consistency, proof verification)
//   Section 5  — InMemoryStore (BlockStore interface)
//   Section 6  — FileSystemStore (BlockStore backend)
//   Section 7  — ReplicationManager (ANNOUNCE / FETCH / REPLICATE, TF-03/TF-05)
//   Section 8  — Benchmarks (throughput mandated by wiki/storage_layer.md)
package storage

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"sync"
	"testing"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

// makeData returns a deterministic byte slice of length n.
func makeData(n int) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = byte(i & 0xFF)
	}
	return buf
}

// makeDataFill fills every byte with a fixed value (useful for large uniform slices).
func makeDataFill(n int, b byte) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return buf
}

// ── Section 1 — ChunkFile ─────────────────────────────────────────────────────

// TestChunkFileSingleChunk verifies that a payload ≤ 256 KB produces one chunk.
func TestChunkFileSingleChunk(t *testing.T) {
	data := makeData(1024) // 1 KB
	chunks, root, err := ChunkFile(data)
	if err != nil {
		t.Fatalf("ChunkFile: %v", err)
	}
	if len(chunks) != 1 {
		t.Errorf("expected 1 chunk, got %d", len(chunks))
	}

	c := chunks[0]
	if c.Index != 0 {
		t.Errorf("chunk.Index = %d, want 0", c.Index)
	}
	if len(c.Data) != 1024 {
		t.Errorf("chunk.Data length = %d, want 1024", len(c.Data))
	}
	want := sha256.Sum256(data)
	if c.CID != CID(want) {
		t.Errorf("chunk.CID mismatch")
	}

	// For a single chunk, MerkleRoot == CID (single-leaf degenerate case).
	if MerkleRoot(c.CID) != root {
		t.Errorf("single-chunk: MerkleRoot should equal the chunk's CID")
	}
}

// TestChunkFileExactBoundary verifies behaviour for a payload of exactly 256 KB.
func TestChunkFileExactBoundary(t *testing.T) {
	data := makeData(ChunkSize) // exactly 256 KB
	chunks, _, err := ChunkFile(data)
	if err != nil {
		t.Fatalf("ChunkFile: %v", err)
	}
	if len(chunks) != 1 {
		t.Errorf("exact 256 KB: expected 1 chunk, got %d", len(chunks))
	}
	if len(chunks[0].Data) != ChunkSize {
		t.Errorf("chunk data length = %d, want %d", len(chunks[0].Data), ChunkSize)
	}
}

// TestChunkFilePlusOneByte verifies that 256 KB + 1 byte produces two chunks:
// a full first chunk and a one-byte tail chunk.
func TestChunkFilePlusOneByte(t *testing.T) {
	data := makeData(ChunkSize + 1)
	chunks, _, err := ChunkFile(data)
	if err != nil {
		t.Fatalf("ChunkFile: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
	if len(chunks[0].Data) != ChunkSize {
		t.Errorf("first chunk length = %d, want %d", len(chunks[0].Data), ChunkSize)
	}
	if len(chunks[1].Data) != 1 {
		t.Errorf("tail chunk length = %d, want 1", len(chunks[1].Data))
	}
	if chunks[1].Index != 1 {
		t.Errorf("tail chunk.Index = %d, want 1", chunks[1].Index)
	}
}

// TestChunkFileMultipleChunks verifies chunk count for a multi-chunk file.
func TestChunkFileMultipleChunks(t *testing.T) {
	// 5.5 chunks worth of data → 6 chunks
	data := makeData(5*ChunkSize + ChunkSize/2)
	chunks, _, err := ChunkFile(data)
	if err != nil {
		t.Fatalf("ChunkFile: %v", err)
	}
	if len(chunks) != 6 {
		t.Errorf("expected 6 chunks, got %d", len(chunks))
	}

	// Assert indices are 0..5 and data is contiguous.
	var reassembled []byte
	for i, c := range chunks {
		if c.Index != uint64(i) {
			t.Errorf("chunk[%d].Index = %d, want %d", i, c.Index, i)
		}
		reassembled = append(reassembled, c.Data...)
	}
	if !bytes.Equal(reassembled, data) {
		t.Error("concatenating chunks does not reproduce original data")
	}
}

// TestChunkFileCIDCorrectness verifies every chunk's CID is SHA-256 of its data.
func TestChunkFileCIDCorrectness(t *testing.T) {
	data := makeData(3*ChunkSize + 100)
	chunks, _, err := ChunkFile(data)
	if err != nil {
		t.Fatalf("ChunkFile: %v", err)
	}
	for _, c := range chunks {
		want := sha256.Sum256(c.Data)
		if CID(want) != c.CID {
			t.Errorf("chunk %d: CID mismatch (want %x, got %x)", c.Index, want, c.CID)
		}
	}
}

// TestChunkFileEmptyRejected verifies that empty input is rejected.
func TestChunkFileEmptyRejected(t *testing.T) {
	_, _, err := ChunkFile(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
	_, _, err = ChunkFile([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

// TestChunkFileDataCopy verifies that mutating the original buffer after ChunkFile
// does not corrupt the stored chunk data (aliasing guard).
func TestChunkFileDataCopy(t *testing.T) {
	data := makeData(100)
	chunks, _, err := ChunkFile(data)
	if err != nil {
		t.Fatalf("ChunkFile: %v", err)
	}
	originalCID := chunks[0].CID

	// Mutate the original slice.
	data[0] ^= 0xFF
	// Chunk must be unaffected.
	if chunks[0].CID != originalCID {
		t.Error("mutating source buffer after ChunkFile changed chunk CID — aliasing bug")
	}
	if chunks[0].Data[0] == data[0] {
		t.Error("chunk Data references original buffer (aliasing bug)")
	}
}

// TestChunkFileDeterministic verifies that two calls with the same input produce
// identical chunks and roots.
func TestChunkFileDeterministic(t *testing.T) {
	data := makeData(ChunkSize + 500)

	chunks1, root1, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}
	chunks2, root2, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}

	if root1 != root2 {
		t.Error("ChunkFile is not deterministic: roots differ")
	}
	if len(chunks1) != len(chunks2) {
		t.Fatal("ChunkFile is not deterministic: chunk counts differ")
	}
	for i := range chunks1 {
		if chunks1[i].CID != chunks2[i].CID {
			t.Errorf("chunk %d CID differs across calls", i)
		}
	}
}

// ── Section 2 — VerifyIntegrity (TS-02) ──────────────────────────────────────

// TestVerifyIntegrityHappyPath is TF-04: VerifyIntegrity=true immediately
// after ChunkFile (no modification).
func TestVerifyIntegrityHappyPath(t *testing.T) {
	for _, size := range []int{1, 100, ChunkSize, 2*ChunkSize + 1, 5*ChunkSize + 7} {
		data := makeData(size)
		chunks, root, err := ChunkFile(data)
		if err != nil {
			t.Fatalf("size=%d ChunkFile: %v", size, err)
		}
		if !VerifyIntegrity(chunks, root) {
			t.Errorf("size=%d: VerifyIntegrity returned false for unmodified chunks", size)
		}
	}
}

// TestVerifyIntegrityTamperedFirstByte is TS-02: flipping byte 0 of chunk 0
// must cause VerifyIntegrity to return false.
func TestVerifyIntegrityTamperedFirstByte(t *testing.T) {
	data := makeData(10 * ChunkSize)
	chunks, root, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper: flip first byte of first chunk.
	tampered := make([]byte, len(chunks[0].Data))
	copy(tampered, chunks[0].Data)
	tampered[0] ^= 0x01

	tamperedChunks := make([]Chunk, len(chunks))
	copy(tamperedChunks, chunks)
	tamperedChunks[0].Data = tampered
	// CID is NOT updated → CID/Data inconsistency must be caught.

	if VerifyIntegrity(tamperedChunks, root) {
		t.Fatal("TS-02 FAIL: VerifyIntegrity returned true for tampered first byte")
	}
}

// TestVerifyIntegrityTamperedLastChunk verifies TS-02 for the tail chunk
// (typically smaller than ChunkSize).
func TestVerifyIntegrityTamperedLastChunk(t *testing.T) {
	data := makeData(2*ChunkSize + 100) // 3 chunks; last is 100 bytes
	chunks, root, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}

	last := len(chunks) - 1
	tampered := make([]byte, len(chunks[last].Data))
	copy(tampered, chunks[last].Data)
	tampered[len(tampered)-1] ^= 0xFF

	tc := make([]Chunk, len(chunks))
	copy(tc, chunks)
	tc[last].Data = tampered

	if VerifyIntegrity(tc, root) {
		t.Fatal("TS-02 FAIL: VerifyIntegrity returned true for tampered tail chunk")
	}
}

// TestVerifyIntegrityTamperedMiddleChunk verifies TS-02 for an interior chunk.
func TestVerifyIntegrityTamperedMiddleChunk(t *testing.T) {
	data := makeData(5 * ChunkSize)
	chunks, root, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper chunk 2 (middle).
	mid := 2
	tampered := make([]byte, len(chunks[mid].Data))
	copy(tampered, chunks[mid].Data)
	tampered[ChunkSize/2] ^= 0xAB

	tc := make([]Chunk, len(chunks))
	copy(tc, chunks)
	tc[mid].Data = tampered

	if VerifyIntegrity(tc, root) {
		t.Fatal("TS-02 FAIL: middle chunk tamper not detected")
	}
}

// TestVerifyIntegrityWrongRoot verifies that unmodified chunks fail against
// a different (wrong) root.
func TestVerifyIntegrityWrongRoot(t *testing.T) {
	data := makeData(ChunkSize + 1)
	chunks, _, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}

	var wrongRoot MerkleRoot
	wrongRoot[0] = 0xFF

	if VerifyIntegrity(chunks, wrongRoot) {
		t.Fatal("VerifyIntegrity returned true for wrong root")
	}
}

// TestVerifyIntegrityEmptyChunks verifies that an empty slice returns false.
func TestVerifyIntegrityEmptyChunks(t *testing.T) {
	if VerifyIntegrity(nil, MerkleRoot{}) {
		t.Fatal("VerifyIntegrity must return false for nil chunks")
	}
	if VerifyIntegrity([]Chunk{}, MerkleRoot{}) {
		t.Fatal("VerifyIntegrity must return false for empty chunks")
	}
}

// TestVerifyIntegrityCIDUpdatedWithTamper verifies that if an attacker also
// updates the CID to match the tampered data, the Merkle root still catches it.
func TestVerifyIntegrityCIDUpdatedWithTamper(t *testing.T) {
	data := makeData(3 * ChunkSize)
	chunks, root, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}

	// Attacker modifies chunk 1 data AND recalculates its CID.
	tampered := make([]byte, len(chunks[1].Data))
	copy(tampered, chunks[1].Data)
	tampered[0] ^= 0x01

	tc := make([]Chunk, len(chunks))
	copy(tc, chunks)
	tc[1].Data = tampered
	tc[1].CID = CID(sha256.Sum256(tampered)) // attacker also updates CID

	// The Merkle root must still fail because the leaf hash has changed.
	if VerifyIntegrity(tc, root) {
		t.Fatal("TS-02 FAIL: attacker updated CID + data, Merkle root should still reject")
	}
}

// ── Section 3 — ReassembleFile (TF-01) ───────────────────────────────────────

// TestReassembleRoundTrip is TF-01: ChunkFile → ReassembleFile → identical bytes.
func TestReassembleRoundTrip(t *testing.T) {
	for _, size := range []int{1, 50, ChunkSize - 1, ChunkSize, ChunkSize + 1, 7*ChunkSize + 99} {
		data := makeData(size)
		chunks, root, err := ChunkFile(data)
		if err != nil {
			t.Fatalf("size=%d ChunkFile: %v", size, err)
		}

		got, err := ReassembleFile(chunks, root)
		if err != nil {
			t.Fatalf("size=%d ReassembleFile: %v", size, err)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("size=%d: round-trip mismatch", size)
		}
	}
}

// TestReassembleOutOfOrder verifies that chunks can arrive in any order and
// ReassembleFile still reconstructs the correct data.
func TestReassembleOutOfOrder(t *testing.T) {
	data := makeData(4 * ChunkSize)
	chunks, root, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}

	// Reverse chunk order.
	reversed := make([]Chunk, len(chunks))
	for i, c := range chunks {
		reversed[len(chunks)-1-i] = c
	}

	got, err := ReassembleFile(reversed, root)
	if err != nil {
		t.Fatalf("ReassembleFile (reversed): %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("out-of-order reassembly produced wrong data")
	}
}

// TestReassembleTamperedChunkRejected verifies TS-02 in ReassembleFile:
// a tampered chunk causes an error, not silent data corruption.
func TestReassembleTamperedChunkRejected(t *testing.T) {
	data := makeData(2*ChunkSize + 1)
	chunks, root, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}

	tampered := make([]byte, len(chunks[0].Data))
	copy(tampered, chunks[0].Data)
	tampered[0] ^= 0x01

	tc := make([]Chunk, len(chunks))
	copy(tc, chunks)
	tc[0].Data = tampered // CID left stale → CID mismatch on reassembly

	_, err = ReassembleFile(tc, root)
	if err == nil {
		t.Fatal("TS-02: ReassembleFile must reject a tampered chunk")
	}
}

// TestReassembleEmptyChunks verifies the empty-slice guard.
func TestReassembleEmptyChunks(t *testing.T) {
	_, err := ReassembleFile(nil, MerkleRoot{})
	if err == nil {
		t.Fatal("expected error for nil chunks")
	}
}

// TestReassembleIndexGap verifies that a gap in chunk indices is detected.
func TestReassembleIndexGap(t *testing.T) {
	data := makeData(2 * ChunkSize)
	chunks, root, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}

	// Skip chunk 0 → gap at position 0.
	_, err = ReassembleFile(chunks[1:], root)
	if err == nil {
		t.Fatal("expected error for missing chunk 0")
	}
}

// TestReassembleCIDUpdatedByAttacker mirrors TestVerifyIntegrityCIDUpdatedWithTamper
// at the ReassembleFile level: both CID and data changed → Merkle root rejects.
func TestReassembleCIDUpdatedByAttacker(t *testing.T) {
	data := makeData(3 * ChunkSize)
	chunks, root, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}

	tampered := make([]byte, len(chunks[0].Data))
	copy(tampered, chunks[0].Data)
	tampered[0] ^= 0x01

	tc := make([]Chunk, len(chunks))
	copy(tc, chunks)
	tc[0].Data = tampered
	tc[0].CID = CID(sha256.Sum256(tampered)) // attacker also recalculates CID

	_, err = ReassembleFile(tc, root)
	if err == nil {
		t.Fatal("ReassembleFile must reject even when attacker recalculates the CID")
	}
}

// ── Section 4 — Merkle tree ───────────────────────────────────────────────────

// TestMerkleRootConsistency verifies that MerkleRootFromChunks agrees with the
// root returned by ChunkFile for all tested sizes.
func TestMerkleRootConsistency(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 7, 8, 9, 16} {
		data := makeData(n * ChunkSize)
		chunks, rootFromChunkFile, err := ChunkFile(data)
		if err != nil {
			t.Fatalf("n=%d ChunkFile: %v", n, err)
		}

		rootFromFunc, err := MerkleRootFromChunks(chunks)
		if err != nil {
			t.Fatalf("n=%d MerkleRootFromChunks: %v", n, err)
		}
		if rootFromFunc != rootFromChunkFile {
			t.Errorf("n=%d: MerkleRootFromChunks ≠ ChunkFile root", n)
		}
	}
}

// TestMerkleRootSingleLeafEquality verifies that for a single chunk the root
// equals the chunk's CID (degenerate tree).
func TestMerkleRootSingleLeafEquality(t *testing.T) {
	data := makeData(1000)
	chunks, root, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}
	if root != MerkleRoot(chunks[0].CID) {
		t.Error("single-chunk: MerkleRoot ≠ chunk CID")
	}
}

// TestMerkleRootOddLeafCount verifies that odd-numbered leaf counts (which
// require last-node duplication) produce a consistent, deterministic root.
func TestMerkleRootOddLeafCount(t *testing.T) {
	data := makeData(3 * ChunkSize) // 3 leaves (odd)
	chunks, root, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}

	// Recompute independently.
	got, err := MerkleRootFromChunks(chunks)
	if err != nil {
		t.Fatal(err)
	}
	if got != root {
		t.Error("odd-leaf: recomputed root differs from ChunkFile root")
	}
}

// TestMerkleRootFromHashesAgreement verifies MerkleRootFromHashes produces the
// same result as MerkleRootFromChunks.
func TestMerkleRootFromHashesAgreement(t *testing.T) {
	data := makeData(4*ChunkSize + 1)
	chunks, expected, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}

	hashes := make([][32]byte, len(chunks))
	for i, c := range chunks {
		hashes[i] = [32]byte(c.CID)
	}
	got, err := MerkleRootFromHashes(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if got != expected {
		t.Error("MerkleRootFromHashes ≠ MerkleRootFromChunks")
	}
}

// TestMerkleRootFromHashesEmptyRejected verifies that an empty hash slice errors.
func TestMerkleRootFromHashesEmptyRejected(t *testing.T) {
	_, err := MerkleRootFromHashes(nil)
	if err == nil {
		t.Fatal("expected error for nil hashes")
	}
	_, err = MerkleRootFromHashes([][32]byte{})
	if err == nil {
		t.Fatal("expected error for empty hashes")
	}
}

// TestMerkleProofRoundTrip generates a proof for every leaf and verifies it.
func TestMerkleProofRoundTrip(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 7, 8, 9} {
		data := makeData(n * ChunkSize)
		chunks, root, err := ChunkFile(data)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}

		for i := range chunks {
			proof, err := GenerateMerkleProof(chunks, uint64(i))
			if err != nil {
				t.Fatalf("n=%d leaf=%d: GenerateMerkleProof: %v", n, i, err)
			}

			leafHash := [32]byte(chunks[i].CID)
			if !VerifyMerkleProof(leafHash, proof, root) {
				t.Errorf("n=%d leaf=%d: VerifyMerkleProof returned false for valid proof", n, i)
			}
		}
	}
}

// TestMerkleProofWrongLeaf verifies that a proof for one leaf fails for another.
//
// NOTE: data must produce chunks with distinct CIDs.  makeData(4*ChunkSize)
// cannot be used because ChunkSize = 256×1024 is an exact multiple of 256, so
// every chunk's byte content is the same repeating pattern (0x00…0xFF × 1024)
// → identical SHA-256.  Instead we fill each chunk with a different constant
// byte, guaranteeing all four CIDs are distinct.
func TestMerkleProofWrongLeaf(t *testing.T) {
	const n = 4
	data := make([]byte, n*ChunkSize)
	for i := 0; i < n; i++ {
		// Fill chunk i with a distinct constant: 0x11, 0x22, 0x33, 0x44.
		fill := byte(0x11 * (i + 1))
		for j := 0; j < ChunkSize; j++ {
			data[i*ChunkSize+j] = fill
		}
	}

	chunks, root, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity-check: all CIDs are distinct (the test would be vacuous otherwise).
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if chunks[i].CID == chunks[j].CID {
				t.Fatalf("setup error: chunk %d and chunk %d have the same CID", i, j)
			}
		}
	}

	proof0, err := GenerateMerkleProof(chunks, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Use chunk 1's hash with chunk 0's proof — must fail because the proof
	// path was built for leaf 0, not leaf 1.
	leafHash1 := [32]byte(chunks[1].CID)
	if VerifyMerkleProof(leafHash1, proof0, root) {
		t.Fatal("wrong leaf passed with a mismatched proof — should fail")
	}
}

// TestMerkleProofOutOfRangeRejected verifies GenerateMerkleProof rejects an
// out-of-range index.
func TestMerkleProofOutOfRangeRejected(t *testing.T) {
	data := makeData(ChunkSize)
	chunks, _, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}

	_, err = GenerateMerkleProof(chunks, uint64(len(chunks))) // == len → out of range
	if err == nil {
		t.Fatal("expected error for out-of-range leaf index")
	}
	_, err = GenerateMerkleProof(nil, 0) // empty chunks
	if err == nil {
		t.Fatal("expected error for nil chunks")
	}
}

// TestMerkleProofTamperedLeafRejected verifies that a tampered leaf hash
// fails VerifyMerkleProof.
func TestMerkleProofTamperedLeafRejected(t *testing.T) {
	data := makeData(3 * ChunkSize)
	chunks, root, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := GenerateMerkleProof(chunks, 0)
	if err != nil {
		t.Fatal(err)
	}

	var tamperedHash [32]byte
	copy(tamperedHash[:], chunks[0].CID[:])
	tamperedHash[0] ^= 0x01 // flip one bit

	if VerifyMerkleProof(tamperedHash, proof, root) {
		t.Fatal("VerifyMerkleProof should reject a tampered leaf hash")
	}
}

// ── Section 5 — InMemoryStore ─────────────────────────────────────────────────

// TestInMemoryPutGetHas is the basic round-trip for the InMemoryStore.
func TestInMemoryPutGetHas(t *testing.T) {
	store := NewInMemoryStore()

	data := []byte("hello, ztss blockstore")
	cid := CID(sha256.Sum256(data))

	if store.Has(cid) {
		t.Error("Has returned true before Put")
	}
	if err := store.Put(cid, data); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !store.Has(cid) {
		t.Error("Has returned false after Put")
	}

	got, err := store.Get(cid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("Get returned different bytes than Put")
	}
}

// TestInMemoryGetNotFound verifies ErrNotFound is returned for missing CIDs.
func TestInMemoryGetNotFound(t *testing.T) {
	store := NewInMemoryStore()
	var cid CID
	cid[0] = 0xDE

	_, err := store.Get(cid)
	if err == nil {
		t.Fatal("Get must fail for absent CID")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

// TestInMemoryPutIdempotent verifies that calling Put twice with the same CID
// does not corrupt the stored value.
func TestInMemoryPutIdempotent(t *testing.T) {
	store := NewInMemoryStore()
	data := []byte("idempotent test")
	cid := CID(sha256.Sum256(data))

	if err := store.Put(cid, data); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(cid, data); err != nil {
		t.Fatal(err)
	}

	got, err := store.Get(cid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Error("data corrupted by second Put")
	}
	if store.Len() != 1 {
		t.Errorf("expected 1 entry after two Puts with same CID, got %d", store.Len())
	}
}

// TestInMemoryGetReturnsCopy verifies that mutating the returned slice does not
// affect the stored value (defensive copy guarantee).
func TestInMemoryGetReturnsCopy(t *testing.T) {
	store := NewInMemoryStore()
	data := []byte{0x01, 0x02, 0x03}
	cid := CID(sha256.Sum256(data))

	store.Put(cid, data)

	got, _ := store.Get(cid)
	got[0] = 0xFF // mutate the returned copy

	got2, _ := store.Get(cid)
	if got2[0] == 0xFF {
		t.Error("Get does not return a defensive copy — stored value was mutated")
	}
}

// TestInMemoryPutDoesNotAlias verifies that mutating the original slice after
// Put does not affect the stored value.
func TestInMemoryPutDoesNotAlias(t *testing.T) {
	store := NewInMemoryStore()
	data := []byte{0x0A, 0x0B, 0x0C}
	cid := CID(sha256.Sum256(data))

	store.Put(cid, data)
	data[0] = 0xFF // mutate original

	got, _ := store.Get(cid)
	if got[0] == 0xFF {
		t.Error("Put does not copy — mutating original affected stored value")
	}
}

// TestInMemoryStoreLen verifies the Len helper.
func TestInMemoryStoreLen(t *testing.T) {
	store := NewInMemoryStore()
	for i := 0; i < 5; i++ {
		d := []byte{byte(i)}
		store.Put(CID(sha256.Sum256(d)), d)
	}
	if store.Len() != 5 {
		t.Errorf("Len = %d, want 5", store.Len())
	}
}

// TestInMemoryConcurrentAccess verifies thread safety under concurrent Put/Get/Has.
func TestInMemoryConcurrentAccess(t *testing.T) {
	store := NewInMemoryStore()
	data := makeData(1024)
	cid := CID(sha256.Sum256(data))

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			store.Put(cid, data)
		}()
		go func() {
			defer wg.Done()
			store.Get(cid)
		}()
		go func() {
			defer wg.Done()
			store.Has(cid)
		}()
	}
	wg.Wait()
	// If the test doesn't deadlock or race-detect, it passes.
}

// ── Section 6 — FileSystemStore ───────────────────────────────────────────────

// TestFileSystemStoreRoundTrip verifies Put → Get → Has for the filesystem backend.
func TestFileSystemStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileSystemStore(dir)
	if err != nil {
		t.Fatalf("NewFileSystemStore: %v", err)
	}

	data := []byte("filesystem chunk data")
	cid := CID(sha256.Sum256(data))

	if store.Has(cid) {
		t.Error("Has returned true before Put")
	}
	if err := store.Put(cid, data); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !store.Has(cid) {
		t.Error("Has returned false after Put")
	}

	got, err := store.Get(cid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("Get returned different bytes than Put")
	}
}

// TestFileSystemStoreNotFound verifies ErrNotFound wrap for the FS backend.
func TestFileSystemStoreNotFound(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileSystemStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	var cid CID
	cid[0] = 0xAB
	_, err = store.Get(cid)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

// TestFileSystemStorePutIdempotent verifies double-Put does not corrupt data.
func TestFileSystemStorePutIdempotent(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFileSystemStore(dir)

	data := []byte("idempotent fs put")
	cid := CID(sha256.Sum256(data))

	store.Put(cid, data)
	store.Put(cid, data) // second call must not error or corrupt

	got, err := store.Get(cid)
	if err != nil || !bytes.Equal(got, data) {
		t.Errorf("data corrupted after double Put: err=%v", err)
	}
}

// TestFileSystemStoreAllChunks verifies that all chunks from a multi-chunk file
// survive a Put/Get round-trip through the filesystem backend.
func TestFileSystemStoreAllChunks(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewFileSystemStore(dir)

	data := makeData(4*ChunkSize + 100)
	chunks, _, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range chunks {
		if err := store.Put(c.CID, c.Data); err != nil {
			t.Fatalf("Put chunk %d: %v", c.Index, err)
		}
	}
	for _, c := range chunks {
		got, err := store.Get(c.CID)
		if err != nil {
			t.Fatalf("Get chunk %d: %v", c.Index, err)
		}
		if !bytes.Equal(got, c.Data) {
			t.Errorf("chunk %d: data mismatch after FS round-trip", c.Index)
		}
	}
}

// ── Section 7 — ReplicationManager (TF-03 / TF-05) ─────────────────────────

func newReplManager(t *testing.T, numPeers, k int) (*ReplicationManager, *InMemoryStore, []*InMemoryStore) {
	t.Helper()
	local := NewInMemoryStore()
	peers := make([]BlockStore, numPeers)
	rawPeers := make([]*InMemoryStore, numPeers)
	for i := 0; i < numPeers; i++ {
		p := NewInMemoryStore()
		rawPeers[i] = p
		peers[i] = p
	}
	rm, err := NewReplicationManager(local, peers, k)
	if err != nil {
		t.Fatalf("NewReplicationManager: %v", err)
	}
	return rm, local, rawPeers
}

// TestReplicateTF03 is TF-03: after Replicate, Has(cid)==true on ≥ k=3 nodes.
func TestReplicateTF03(t *testing.T) {
	rm, local, peers := newReplManager(t, 5, 3)

	data := makeData(1024)
	cid := CID(sha256.Sum256(data))

	// Store locally before replicating.
	local.Put(cid, data)

	if err := rm.Replicate(cid); err != nil {
		t.Fatalf("Replicate: %v", err)
	}

	// Count total holders.
	holders := 0
	if local.Has(cid) {
		holders++
	}
	for _, p := range peers {
		if p.Has(cid) {
			holders++
		}
	}

	if holders < 3 {
		t.Errorf("TF-03 FAIL: only %d holders, need ≥ 3", holders)
	}
}

// TestReplicateNotEnoughPeersFails verifies that Replicate returns an error
// when fewer peers than k are available.
func TestReplicateNotEnoughPeersFails(t *testing.T) {
	// k=3 but only 1 peer → can reach 2 holders at most.
	rm, local, _ := newReplManager(t, 1, 3)

	data := makeData(512)
	cid := CID(sha256.Sum256(data))
	local.Put(cid, data)

	err := rm.Replicate(cid)
	if err == nil {
		t.Fatal("Replicate must fail when fewer than k replicas possible")
	}
}

// TestFetchTF05 is TF-05: Fetch pulls a chunk from a peer when absent locally.
func TestFetchTF05(t *testing.T) {
	rm, local, peers := newReplManager(t, 3, 3)

	data := makeData(2048)
	cid := CID(sha256.Sum256(data))

	// Only peer[1] has the chunk.
	peers[1].Put(cid, data)

	if err := rm.Fetch(cid); err != nil {
		t.Fatalf("TF-05 FAIL: Fetch: %v", err)
	}
	if !local.Has(cid) {
		t.Fatal("TF-05 FAIL: local store does not have the fetched chunk")
	}

	got, err := local.Get(cid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Error("fetched chunk data does not match original")
	}
}

// TestFetchAlreadyLocal verifies that Fetch is a no-op when the chunk is
// already in the local store.
func TestFetchAlreadyLocal(t *testing.T) {
	rm, local, _ := newReplManager(t, 2, 2)

	data := []byte("already local")
	cid := CID(sha256.Sum256(data))
	local.Put(cid, data)

	if err := rm.Fetch(cid); err != nil {
		t.Fatalf("Fetch for locally-present chunk: %v", err)
	}
}

// TestFetchNotFound verifies ErrNotFound when no peer has the chunk.
func TestFetchNotFound(t *testing.T) {
	rm, _, _ := newReplManager(t, 3, 3)
	var cid CID
	cid[0] = 0xFF

	err := rm.Fetch(cid)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

// TestFetchIntegrityCheck verifies that Fetch rejects data from a peer whose
// CID doesn't match the received bytes (compromised peer, TS-02 at the
// replication layer).
func TestFetchIntegrityCheck(t *testing.T) {
	rm, _, peers := newReplManager(t, 2, 2)

	// Peer holds correct CID but corrupt data.
	realData := []byte("authentic chunk")
	realCID := CID(sha256.Sum256(realData))

	corruptData := []byte("CORRUPTED DATA!!")
	// Put the CORRUPT bytes but under the CORRECT CID key.
	peers[0].store[realCID] = corruptData // direct map access to bypass copy

	err := rm.Fetch(realCID)
	if !errors.Is(err, ErrFetchIntegrityFail) {
		t.Errorf("expected ErrFetchIntegrityFail, got: %v", err)
	}
}

// TestAnnounceReturnsAllPeers verifies Announce returns all peers when the
// chunk is present locally.
func TestAnnounceReturnsAllPeers(t *testing.T) {
	rm, local, _ := newReplManager(t, 4, 4)

	data := []byte("announce test")
	cid := CID(sha256.Sum256(data))
	local.Put(cid, data)

	acked := rm.Announce(cid)
	if len(acked) != 4 {
		t.Errorf("Announce: expected 4 peers acknowledged, got %d", len(acked))
	}
}

// TestAnnounceAbsentCIDReturnsNil verifies Announce is a no-op when the chunk
// is not in the local store.
func TestAnnounceAbsentCIDReturnsNil(t *testing.T) {
	rm, _, _ := newReplManager(t, 3, 3)
	var cid CID
	acked := rm.Announce(cid) // not in local store
	if acked != nil {
		t.Errorf("Announce for absent CID must return nil, got %d peers", len(acked))
	}
}

// TestReplicationManagerNilLocalRejected verifies that a nil local store errors.
func TestReplicationManagerNilLocalRejected(t *testing.T) {
	_, err := NewReplicationManager(nil, nil, 3)
	if err == nil {
		t.Fatal("expected error for nil local store")
	}
}

// TestReplicationManagerKZeroRejected verifies k < 1 is rejected.
func TestReplicationManagerKZeroRejected(t *testing.T) {
	local := NewInMemoryStore()
	_, err := NewReplicationManager(local, nil, 0)
	if err == nil {
		t.Fatal("expected error for k=0")
	}
}

// TestReplicateAllPipeline is the full upload pipeline:
// ChunkFile → ReplicateAll → all chunks present on ≥ k=3 nodes.
func TestReplicateAllPipeline(t *testing.T) {
	rm, local, peers := newReplManager(t, 4, 3)
	_ = local

	data := makeData(3*ChunkSize + 500)
	chunks, _, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}

	if err := rm.ReplicateAll(chunks); err != nil {
		t.Fatalf("ReplicateAll: %v", err)
	}

	// Every chunk must be on at least k=3 holders.
	for _, c := range chunks {
		holders := 0
		if local.Has(c.CID) {
			holders++
		}
		for _, p := range peers {
			if p.Has(c.CID) {
				holders++
			}
		}
		if holders < 3 {
			t.Errorf("chunk %d: only %d holders (need ≥ 3)", c.Index, holders)
		}
	}
}

// ── Section 8 — Benchmarks ────────────────────────────────────────────────────

// BenchmarkChunkFile1MB benchmarks chunking a 1 MB payload.
func BenchmarkChunkFile1MB(b *testing.B) {
	data := makeDataFill(1<<20, 0xAB) // 1 MB
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ChunkFile(data)
	}
}

// BenchmarkChunkFile10MB benchmarks chunking a 10 MB payload.
func BenchmarkChunkFile10MB(b *testing.B) {
	data := makeDataFill(10<<20, 0xCD) // 10 MB
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ChunkFile(data)
	}
}

// BenchmarkChunkFile100MB benchmarks chunking a 100 MB payload.
func BenchmarkChunkFile100MB(b *testing.B) {
	data := makeDataFill(100<<20, 0xEF) // 100 MB
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ChunkFile(data)
	}
}

// BenchmarkVerifyIntegrity10MB benchmarks full integrity verification of 10 MB
// of chunks (VerifyIntegrity calls SHA-256 on every byte).
func BenchmarkVerifyIntegrity10MB(b *testing.B) {
	data := makeDataFill(10<<20, 0x01)
	chunks, root, _ := ChunkFile(data)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyIntegrity(chunks, root)
	}
}

// BenchmarkInMemoryPutGet benchmarks concurrent Put/Get throughput for 256 KB chunks.
func BenchmarkInMemoryPutGet(b *testing.B) {
	store := NewInMemoryStore()
	data := makeDataFill(ChunkSize, 0xFF)
	cid := CID(sha256.Sum256(data))
	store.Put(cid, data) // pre-populate

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			store.Get(cid)
		}
	})
}

// TestCIDString verifies the CID hex representation is 64 characters.
func TestCIDString(t *testing.T) {
	data := []byte("test")
	cid := CID(sha256.Sum256(data))
	s := cid.String()
	if len(s) != 64 {
		t.Errorf("CID.String() length = %d, want 64", len(s))
	}
}

// TestMerkleRootString verifies the MerkleRoot hex representation is 64 characters.
func TestMerkleRootString(t *testing.T) {
	data := makeData(ChunkSize)
	_, root, err := ChunkFile(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(root.String()) != 64 {
		t.Errorf("MerkleRoot.String() length = %d, want 64", len(root.String()))
	}
}

// Verify that InMemoryStore and FileSystemStore both satisfy the BlockStore interface
// at compile time.
var _ BlockStore = (*InMemoryStore)(nil)
var _ BlockStore = (*FileSystemStore)(nil)

// TestFileSystemStoreCreatesDir verifies NewFileSystemStore creates the root
// directory if it doesn't exist.
func TestFileSystemStoreCreatesDir(t *testing.T) {
	base := t.TempDir()
	nested := base + "/a/b/c"
	_, err := NewFileSystemStore(nested)
	if err != nil {
		t.Fatalf("NewFileSystemStore should create nested dirs: %v", err)
	}
	if _, err := os.Stat(nested); err != nil {
		t.Errorf("directory was not created: %v", err)
	}
}
