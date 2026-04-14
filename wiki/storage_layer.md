# Storage Layer

**Module:** `ztss-storage/`  
**Owner:** Bensliman Ammar

## Chunking Engine

- Chunk size: **256 KB** fixed
- Chunk address: `CID = SHA-256(chunk_data)`
- Content-addressed (no location coupling)

## Merkle DAG

- `MerkleRoot(H1, …, Hn)` = file descriptor
- Guarantees non-falsification of any chunk
- Required ops: construct, serialize, verify integrity
- `TF-04`: `VerifyIntegrity = true` after reassembly

## BlockStore Interface

```go
type BlockStore interface {
    Put(cid CID, data []byte) error
    Get(cid CID) ([]byte, error)
    Has(cid CID) bool
}
```

Backends required:
- `InMemory` (testing)
- `FileSystem` (production)

## Replication Protocol

- Policy: `k = 3` replicas minimum
- Messages: `ANNOUNCE`, `FETCH`, `REPLICATE`
- `TF-03`: `Has(cid) = true` on ≥ 3 nodes after upload
- `TF-05`: chunk re-fetch succeeds after 1 node failure
- Consistency: **eventual consistency** via vector clocks or CID versioning

## Required Go Interfaces

```go
func ChunkFile(data []byte) ([]Chunk, MerkleRoot, error)
func ReassembleFile(chunks []Chunk, root MerkleRoot) ([]byte, error)
func VerifyIntegrity(chunks []Chunk, root MerkleRoot) bool
```

## Security Constraint

- Nodes store **only ciphertext**, never plaintext (→ [[security_rules#ES2]])
- `TS-02`: Modifying 1 byte of a stored chunk → Merkle reject + alert log

## Benchmarks Required

- Throughput (MB/s) for: 1 MB, 10 MB, 100 MB files
