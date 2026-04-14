// Package storage implements ZTSS content-addressed storage primitives.
//
// This file (chunk.go) provides:
//   - The CID and Chunk types (wiki/database_schema.md §Chunk)
//   - ChunkFile: splits arbitrary data into strict 256 KB chunks, each
//     addressed by CID = SHA-256(chunk_data)
//   - ReassembleFile: reassembles ordered chunks back into the original data
//
// Security constraint (wiki/security_rules.md §ES2):
//   Nodes receive and store only ciphertext; the caller is responsible for
//   encrypting data before passing it to ChunkFile.  This package is agnostic
//   to whether the bytes are plaintext or ciphertext.
//
// Wiki references:
//   - [[storage_layer#Chunking Engine]]
//   - [[database_schema#Chunk]]
package storage

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

// ── Constants ─────────────────────────────────────────────────────────────────

// ChunkSize is the fixed chunk size mandated by the CDC: 256 KiB.
const ChunkSize = 256 * 1024 // 262144 bytes

// ── Types ─────────────────────────────────────────────────────────────────────

// CID is the 32-byte SHA-256 content-identifier for a single chunk.
// Two chunks with identical bytes always have identical CIDs; any single-byte
// difference produces a completely different CID (SHA-256 collision resistance).
// Nodes use CIDs as storage keys (wiki/database_schema.md §BlockStore).
type CID [32]byte

// String returns the CID as a 64-character lowercase hex string, suitable for
// use as a JSON field or filesystem key.
func (c CID) String() string {
	return fmt.Sprintf("%x", c[:])
}

// Chunk is a fixed-size (or tail) slice of encrypted file data, addressed by
// its CID.
//
// Fields:
//   - Index: zero-based position in the original file (determines ordering
//     during reassembly and Merkle leaf ordering).
//   - CID:   SHA-256(Data); computed by ChunkFile, verified by VerifyIntegrity.
//   - Data:  up to ChunkSize bytes.  The final chunk may be shorter.
type Chunk struct {
	Index uint64
	CID   CID
	Data  []byte
}

// ── ChunkFile ─────────────────────────────────────────────────────────────────

// ChunkFile splits data into 256 KB chunks and returns:
//   - chunks: ordered slice of Chunk, each with a precomputed CID.
//   - root:   MerkleRoot of all chunk CIDs (= the file descriptor).
//   - err:    non-nil if data is empty.
//
// Chunking algorithm:
//
//	for i = 0, ChunkSize, 2*ChunkSize, …:
//	    chunk_i.Data = data[i : min(i+ChunkSize, len(data))]
//	    chunk_i.CID  = SHA-256(chunk_i.Data)
//
// The final chunk is a tail chunk of 1 … ChunkSize bytes.
// Empty input is rejected: a file must have at least one byte.
//
// The returned MerkleRoot is computed by MerkleRootFromChunks and can be used
// directly as the "root_cid" field in the POST /upload response
// (wiki/database_schema.md §File Descriptor).
func ChunkFile(data []byte) ([]Chunk, MerkleRoot, error) {
	if len(data) == 0 {
		return nil, MerkleRoot{}, errors.New("ztss/storage: ChunkFile: input data must not be empty")
	}

	n := (len(data) + ChunkSize - 1) / ChunkSize // ceil(len/ChunkSize)
	chunks := make([]Chunk, n)

	for i := 0; i < n; i++ {
		start := i * ChunkSize
		end := start + ChunkSize
		if end > len(data) {
			end = len(data)
		}

		sliceData := data[start:end]
		cid := sha256.Sum256(sliceData)

		// Copy the slice so callers own the chunk data independently of the
		// original buffer.  (Avoids aliasing issues if the caller modifies
		// data after ChunkFile returns.)
		chunkData := make([]byte, len(sliceData))
		copy(chunkData, sliceData)

		chunks[i] = Chunk{
			Index: uint64(i),
			CID:   cid,
			Data:  chunkData,
		}
	}

	root, err := MerkleRootFromChunks(chunks)
	if err != nil {
		return nil, MerkleRoot{}, fmt.Errorf("ztss/storage: ChunkFile: Merkle root: %w", err)
	}

	return chunks, root, nil
}

// ── ReassembleFile ───────────────────────────────────────────────────────────

// ReassembleFile concatenates chunks in ascending Index order to reconstruct
// the original data, then verifies the resulting Merkle root matches root.
//
// Returns an error if:
//   - chunks is empty
//   - any chunk's CID does not match SHA-256(chunk.Data)  (single-chunk integrity)
//   - the recomputed MerkleRoot ≠ root                    (tree-level integrity)
//
// This is the inverse of ChunkFile and satisfies wiki/storage_layer.md §TF-04:
//
//	VerifyIntegrity(chunks, root) == true after reassembly.
//
// Chunks need NOT be pre-sorted; ReassembleFile sorts by Index internally.
// However, gaps or duplicate indices are detected via an index continuity check.
func ReassembleFile(chunks []Chunk, root MerkleRoot) ([]byte, error) {
	if len(chunks) == 0 {
		return nil, errors.New("ztss/storage: ReassembleFile: no chunks provided")
	}

	// Sort chunks by Index (insertion sort — chunk counts are small; O(n²) fine).
	sorted := sortedChunks(chunks)

	// Validate index continuity: must be 0, 1, 2, …, n-1.
	for i, c := range sorted {
		if c.Index != uint64(i) {
			return nil, fmt.Errorf(
				"ztss/storage: ReassembleFile: index gap or duplicate at position %d (got Index %d)",
				i, c.Index,
			)
		}
	}

	// Verify CID of each chunk before touching the data.
	for _, c := range sorted {
		got := sha256.Sum256(c.Data)
		if got != c.CID {
			return nil, fmt.Errorf(
				"ztss/storage: ReassembleFile: chunk %d CID mismatch (got %x, want %x)",
				c.Index, got, c.CID,
			)
		}
	}

	// Verify Merkle root.
	if !VerifyIntegrity(sorted, root) {
		return nil, errors.New("ztss/storage: ReassembleFile: Merkle root verification failed")
	}

	// Concatenate data in order.
	var buf bytes.Buffer
	for _, c := range sorted {
		buf.Write(c.Data)
	}
	return buf.Bytes(), nil
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// sortedChunks returns a copy of the slice sorted by Chunk.Index (ascending).
// Uses a simple insertion sort suitable for the small number of chunks per file.
func sortedChunks(chunks []Chunk) []Chunk {
	out := make([]Chunk, len(chunks))
	copy(out, chunks)
	for i := 1; i < len(out); i++ {
		key := out[i]
		j := i - 1
		for j >= 0 && out[j].Index > key.Index {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = key
	}
	return out
}
