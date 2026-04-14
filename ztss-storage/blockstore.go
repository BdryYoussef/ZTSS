// Package storage implements ZTSS content-addressed storage primitives.
//
// blockstore.go provides:
//
//  1. BlockStore interface — canonical read/write/probe on CID-keyed chunks.
//  2. InMemoryStore  — thread-safe in-process backend (unit tests, TF-01–TF-05).
//  3. FileSystemStore — production backend; one file per CID under a root dir.
//  4. Replication stubs (ReplicationManager) — k=3 policy with ANNOUNCE,
//     FETCH, and REPLICATE operations against peer BlockStores.
//
// Security constraint (wiki/security_rules.md §ES2):
//
//	Nodes must store ONLY ciphertext.  This package stores whatever bytes
//	the caller provides.  The API layer is responsible for enforcing that
//	only encrypted chunk data is passed to Put.
//
// Wiki references:
//   - [[storage_layer#BlockStore Interface]]
//   - [[storage_layer#Replication Protocol]]
//   - [[database_schema#BlockStore Backends]]
package storage

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// ── BlockStore interface ──────────────────────────────────────────────────────

// BlockStore is the canonical storage interface for ZTSS chunk data.
// All implementations must be safe for concurrent use.
//
// Key:   CID — SHA-256 content identifier (32 bytes).
// Value: raw []byte — always ciphertext in production (ES2).
//
//	type BlockStore interface {
//	    Put(cid CID, data []byte) error
//	    Get(cid CID) ([]byte, error)
//	    Has(cid CID) bool
//	}
type BlockStore interface {
	// Put stores data under its content address cid.
	// Implementations must be idempotent: calling Put with the same cid twice
	// must not corrupt the stored value.
	Put(cid CID, data []byte) error

	// Get retrieves the chunk identified by cid.
	// Returns ErrNotFound if the cid is not present.
	Get(cid CID) ([]byte, error)

	// Has returns true iff the store contains an entry for cid.
	// Must not return an error; unavailability is represented as false.
	Has(cid CID) bool
}

// ErrNotFound is returned by Get when a CID is absent from the store.
var ErrNotFound = errors.New("ztss/storage: CID not found")

// ── InMemoryStore ─────────────────────────────────────────────────────────────

// InMemoryStore is a thread-safe, in-process BlockStore backend backed by a
// Go map.  Used for unit tests and for ephemeral staging of chunks before
// replication.
//
// Usage:
//
//	store := NewInMemoryStore()
//	store.Put(cid, data)
//	data, err := store.Get(cid)
type InMemoryStore struct {
	mu    sync.RWMutex
	store map[CID][]byte
}

// NewInMemoryStore creates an empty InMemoryStore.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{store: make(map[CID][]byte)}
}

// Put stores a copy of data under cid.  The copy prevents the caller from
// mutating stored bytes by modifying the original slice.
func (s *InMemoryStore) Put(cid CID, data []byte) error {
	cp := make([]byte, len(data))
	copy(cp, data)

	s.mu.Lock()
	s.store[cid] = cp
	s.mu.Unlock()
	return nil
}

// Get retrieves a copy of the stored bytes for cid.  Returns ErrNotFound if
// absent.  The copy prevents the caller from indirectly mutating stored data.
func (s *InMemoryStore) Get(cid CID) ([]byte, error) {
	s.mu.RLock()
	v, ok := s.store[cid]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, cid)
	}

	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

// Has returns true iff cid exists in the store.
func (s *InMemoryStore) Has(cid CID) bool {
	s.mu.RLock()
	_, ok := s.store[cid]
	s.mu.RUnlock()
	return ok
}

// Len returns the number of chunks currently held (useful in tests).
func (s *InMemoryStore) Len() int {
	s.mu.RLock()
	n := len(s.store)
	s.mu.RUnlock()
	return n
}

// ── FileSystemStore ──────────────────────────────────────────────────────────

// FileSystemStore is a production BlockStore backed by the OS filesystem.
// Each chunk is stored as a file:
//
//	<RootDir>/<hex-encoded CID>
//
// The directory layout is flat (no subdirectories) for simplicity.  For very
// large deployments a two-level sharded layout (first 2 hex chars as subdir)
// can be introduced without changing the interface.
//
// Usage:
//
//	store, err := NewFileSystemStore("/var/ztss/chunks")
//	if err != nil { … }
//	store.Put(cid, data)
type FileSystemStore struct {
	rootDir string
	mu      sync.RWMutex // serialises concurrent FS access on the same store
}

// NewFileSystemStore creates a FileSystemStore rooted at rootDir, creating the
// directory (and any parents) if it does not already exist.
func NewFileSystemStore(rootDir string) (*FileSystemStore, error) {
	if err := os.MkdirAll(rootDir, 0o700); err != nil {
		return nil, fmt.Errorf("ztss/storage: FileSystemStore: mkdir %q: %w", rootDir, err)
	}
	return &FileSystemStore{rootDir: rootDir}, nil
}

// cidPath returns the absolute filesystem path for a given CID.
func (s *FileSystemStore) cidPath(cid CID) string {
	return filepath.Join(s.rootDir, cid.String())
}

// Put atomically writes data to a temp file then renames it into place.
// The rename is atomic on most POSIX filesystems, preventing corrupt reads
// during concurrent writes.
func (s *FileSystemStore) Put(cid CID, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	target := s.cidPath(cid)

	// Write to a temp file in the same directory (ensures same mount point
	// for atomic rename).
	tmp, err := os.CreateTemp(s.rootDir, ".tmp-")
	if err != nil {
		return fmt.Errorf("ztss/storage: FileSystemStore.Put: create temp: %w", err)
	}
	tmpName := tmp.Name()

	// Cleanup the temp file on any error after this point.
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}

	if _, err = tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("ztss/storage: FileSystemStore.Put: write %s: %w", cid, err)
	}
	if err = tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("ztss/storage: FileSystemStore.Put: sync %s: %w", cid, err)
	}
	if err = tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("ztss/storage: FileSystemStore.Put: close %s: %w", cid, err)
	}

	if err = os.Rename(tmpName, target); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("ztss/storage: FileSystemStore.Put: rename %s: %w", cid, err)
	}
	return nil
}

// Get reads and returns the stored bytes for cid.
// Returns ErrNotFound if no file exists for this CID.
func (s *FileSystemStore) Get(cid CID) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.cidPath(cid))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, cid)
		}
		return nil, fmt.Errorf("ztss/storage: FileSystemStore.Get %s: %w", cid, err)
	}
	return data, nil
}

// Has returns true iff the file for cid exists on disk.
func (s *FileSystemStore) Has(cid CID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, err := os.Stat(s.cidPath(cid))
	return err == nil
}

// ── Replication ───────────────────────────────────────────────────────────────

// ReplicationManager enforces the k=3 replica policy described in
// wiki/storage_layer.md §Replication Protocol.
//
// It operates over a set of peer BlockStores (representing remote nodes in a
// real deployment; use InMemoryStore for integration tests).  The three
// protocol operations are:
//
//	ANNOUNCE  — notify peers that this node has a new CID available.
//	FETCH     — pull a chunk from any peer that has it (maps to GET 0x02).
//	REPLICATE — push a chunk to peers until k replicas are confirmed.
//
// In production, peer BlockStores are backed by the ztss-node/ TCP transport
// (ztss-node/transfer.go).  At the storage layer we depend only on the
// BlockStore interface, keeping the layers independent.
//
// Replication is best-effort with eventual consistency (vector-clock or CID
// versioning can be layered on top for strict consistency if required).
type ReplicationManager struct {
	local  BlockStore
	peers  []BlockStore
	k      int // minimum replica count (default 3)
	logger *log.Logger
}

// NewReplicationManager creates a ReplicationManager.
//
//   - local: the calling node's own BlockStore.
//   - peers: BlockStores representing peer nodes.  In production these are
//     network-backed clients; in tests they are InMemoryStores.
//   - k: minimum replica count (must be ≥ 1; CDC mandates k=3).
func NewReplicationManager(local BlockStore, peers []BlockStore, k int) (*ReplicationManager, error) {
	if local == nil {
		return nil, errors.New("ztss/storage: ReplicationManager: local store must not be nil")
	}
	if k < 1 {
		return nil, fmt.Errorf("ztss/storage: ReplicationManager: k must be ≥ 1, got %d", k)
	}
	return &ReplicationManager{
		local:  local,
		peers:  peers,
		k:      k,
		logger: log.New(log.Writer(), "[replication] ", log.LstdFlags),
	}, nil
}

// ── ANNOUNCE ────────────────────────────────────────────────────────────────

// Announce broadcasts to all peers that this node now holds the chunk
// identified by cid.  Peers may choose to FETCH the chunk opportunistically.
//
// Wire mapping: this corresponds to sending a Type=0x03 (ANNOUNCE) message
// in the binary wire protocol (wiki/network_layer.md §Binary Wire Protocol).
//
// In this stub the "broadcast" is simulated by logging.  The ztss-node/ layer
// sends the actual bytes over TLS 1.3 / NOISE connections.
//
// Returns a list of peers that acknowledged the announcement.
func (rm *ReplicationManager) Announce(cid CID) []BlockStore {
	if !rm.local.Has(cid) {
		rm.logger.Printf("ANNOUNCE skipped — local store does not have %s", cid)
		return nil
	}

	acknowledged := make([]BlockStore, 0, len(rm.peers))
	for i, peer := range rm.peers {
		// Stub: in production, send Type=0x03 ANNOUNCE over the TCP connection.
		// The peer's node.go handler records the CID in its routing table and
		// may initiate a FETCH.
		rm.logger.Printf("ANNOUNCE cid=%s to peer[%d]", cid, i)
		acknowledged = append(acknowledged, peer)
	}
	return acknowledged
}

// ── FETCH ───────────────────────────────────────────────────────────────────

// Fetch retrieves the chunk for cid from the first available peer and stores
// it in the local BlockStore.
//
// Wire mapping: sends a Type=0x02 (GET) message to each peer in turn until
// one responds with the chunk data.
//
// Returns ErrNotFound if no peer holds the chunk.
// Returns ErrFetchIntegrityFail if the received data's SHA-256 ≠ cid (TS-02).
func (rm *ReplicationManager) Fetch(cid CID) error {
	if rm.local.Has(cid) {
		rm.logger.Printf("FETCH %s — already present locally", cid)
		return nil
	}

	for i, peer := range rm.peers {
		if !peer.Has(cid) {
			continue
		}

		data, err := peer.Get(cid)
		if err != nil {
			rm.logger.Printf("FETCH %s from peer[%d]: Get error: %v", cid, i, err)
			continue
		}

		// Integrity check before storing: SHA-256(received data) must equal cid.
		// This prevents a compromised peer from injecting corrupt chunks.
		computed := hashBytes(data)
		if computed != cid {
			rm.logger.Printf(
				"FETCH %s from peer[%d]: integrity FAIL (got CID %s)",
				cid, i, CID(computed),
			)
			return fmt.Errorf("%w: CID mismatch from peer[%d]", ErrFetchIntegrityFail, i)
		}

		if err = rm.local.Put(cid, data); err != nil {
			return fmt.Errorf("ztss/storage: Fetch: local Put: %w", err)
		}

		rm.logger.Printf("FETCH %s from peer[%d]: OK", cid, i)
		return nil
	}

	return fmt.Errorf("%w: %s", ErrNotFound, cid)
}

// ── REPLICATE ───────────────────────────────────────────────────────────────

// Replicate pushes the chunk identified by cid to enough peers so that the
// total replica count (local + peers) reaches rm.k.
//
// Wire mapping: sends a Type=0x01 (STORE) message to each target peer,
// carrying the chunk data as the wire payload.
//
// Returns an error if the chunk is not in the local store, or if fewer than
// rm.k total holders can be confirmed after the replication attempt.
//
// TF-03: Has(cid) == true on ≥ 3 distinct nodes after a successful Replicate.
func (rm *ReplicationManager) Replicate(cid CID) error {
	data, err := rm.local.Get(cid)
	if err != nil {
		return fmt.Errorf("ztss/storage: Replicate: local Get: %w", err)
	}

	// Count existing holders (local + peers that already have it).
	holders := 0
	if rm.local.Has(cid) {
		holders++
	}
	for _, peer := range rm.peers {
		if peer.Has(cid) {
			holders++
		}
	}

	// Push to peers until we reach k total holders.
	for i, peer := range rm.peers {
		if holders >= rm.k {
			break
		}
		if peer.Has(cid) {
			continue // already counted above
		}

		// Stub: in production, send Type=0x01 STORE message with data payload
		// over the TLS 1.3 / NOISE connection managed by ztss-node/transfer.go.
		if err = peer.Put(cid, data); err != nil {
			rm.logger.Printf("REPLICATE %s to peer[%d]: Put error: %v", cid, i, err)
			continue
		}

		rm.logger.Printf("REPLICATE %s to peer[%d]: OK", cid, i)
		holders++
	}

	if holders < rm.k {
		return fmt.Errorf(
			"ztss/storage: Replicate: only %d/%d replicas confirmed for %s",
			holders, rm.k, cid,
		)
	}

	rm.logger.Printf("REPLICATE %s: %d/%d replicas confirmed ✓", cid, holders, rm.k)
	return nil
}

// ── ReplicateAll ─────────────────────────────────────────────────────────────

// ReplicateAll calls Replicate for every chunk in chunks.
// Reports the first error encountered; all other chunks are still attempted.
//
// This is a convenience wrapper for the upload path:
//
//	chunks, root, _ := ChunkFile(ciphertext)
//	rm.ReplicateAll(chunks)
func (rm *ReplicationManager) ReplicateAll(chunks []Chunk) error {
	var first error
	for _, c := range chunks {
		if err := rm.local.Put(c.CID, c.Data); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		if err := rm.Replicate(c.CID); err != nil {
			rm.logger.Printf("ReplicateAll: chunk %s: %v", c.CID, err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

// ── Sentinel errors ──────────────────────────────────────────────────────────

// ErrFetchIntegrityFail is returned by Fetch when the received chunk's SHA-256
// does not match the requested CID — indicating a compromised or corrupt peer.
var ErrFetchIntegrityFail = errors.New("ztss/storage: fetch integrity check failed")

// ── Internal helpers ─────────────────────────────────────────────────────────

// hashBytes computes SHA-256 over b and returns it as a [32]byte.
// Used by Fetch to verify that received chunk data matches the requested CID
// before writing to the local store (prevents corrupt-peer injection, TS-02).
func hashBytes(b []byte) [32]byte {
	return sha256.Sum256(b)
}
