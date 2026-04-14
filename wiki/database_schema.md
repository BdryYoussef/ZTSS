# Data Schema

> No relational DB. All persistence is content-addressed via [[storage_layer#BlockStore Interface]].

## Core Data Types

### Chunk

```
CID     = SHA-256(chunk_data)   // 32 bytes, content address
Data    = []byte                // max 256 KB
```

### MerkleRoot

```
R = MerkleRoot(H1, H2, …, Hn)  // binary Merkle tree of chunk CIDs
                                 // serves as the file descriptor / file ID
```

### File Descriptor (implicit)

```
root_cid:      MerkleRoot       // unique file identifier
chunks_count:  int
```

Returned by `POST /upload`:
```json
{ "root_cid": "<hex>", "chunks_count": <int> }
```

### Identity Record

```
identity_id:   string           // server-assigned
public_key:    []byte           // Ed25519 public key (for PoP)
```

Returned by `POST /auth/register`:
```json
{ "public_key": "<base64>", "identity_id": "<uuid>" }
```

### Re-Encryption Key

```
re_key:         ReKey           // ECIES re-key: rkA→B = ReKeyGen(SKA, PKB)
delegated_cid:  CID             // Merkle root of delegated file
```

Returned by `POST /share`:
```json
{ "re_key": "<base64>", "delegated_cid": "<hex>" }
```

### Audit Log Entry

```
timestamp:  RFC3339 string
action:     string              // e.g. "upload", "download", "share"
sig:        []byte              // EdDSA signature over (timestamp + action)
```

Returned by `GET /audit`:
```json
[{ "timestamp": "...", "action": "...", "sig": "<base64>" }]
```

## BlockStore Backends

| Backend | Use Case |
|---------|----------|
| `InMemory` | Unit tests |
| `FileSystem` | Production nodes |

Key: `CID` (32-byte SHA-256). Value: raw `[]byte` (always ciphertext).

## Encrypted Key Storage

- `Kenc = ECIES(PKdest, Kfile)` sent alongside upload, **not stored on nodes**
- Nodes only store opaque ciphertext chunks
