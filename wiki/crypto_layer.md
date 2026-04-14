# Crypto Layer

**Module:** `ztss-crypto/`  
**Owner:** Youssef Badry

## Primitives

- **Symmetric:** AES-256-GCM, random nonce 96 bits
- **KDF:** HKDF for sub-key derivation
- **Asymmetric:** ECIES on **Curve25519**
- **Signatures:** EdDSA (for [[auth_requirements#Proof-of-Possession|PoP]])
- **Hash:** SHA-256 (chunk addressing)

## Secure Upload Flow

1. `Kfile ← CSPRNG(256)` — per-file random key
2. `C ← AES-GCM(Kfile, plaintext, nonce)`
3. Split C into **256 KB chunks**, each addressed by `Hi = SHA-256(chunki)`
4. `R = MerkleRoot(H1 … Hn)` → file descriptor
5. Client signs upload request with private key (PoP); node validates **JWT + PoP** before persisting
6. `Kenc ← ECIES(PKdest, Kfile)` — key encrypted for recipient

## Proxy Re-Encryption (PRE)

```
rkA→B = ReKeyGen(SKA, PKB)        # computed by A only
CB    = ReEncrypt(rkA→B, CA)      # computed by proxy node, no decryption
P     = Decrypt(SKB, CB)          # computed by B
```

- Proxy node **never holds SKA or SKB**
- Proxy **cannot decrypt CA or CB** individually
- Fallback if PRE unimplementable: plain ECIES (no re-encryption)

## Required Go Interfaces

```go
func EncryptFile(plaintext []byte, key []byte) (ciphertext []byte, nonce []byte, err error)
func DecryptFile(ciphertext, nonce, key []byte) ([]byte, error)
func ReKeyGen(skA PrivKey, pkB PubKey) ReKey
func ReEncrypt(rk ReKey, ciphertext []byte) ([]byte, error)
func ProofOfPossession(sk PrivKey, challenge []byte) Signature
```

## Test Requirements

- Coverage **≥ 80%** on crypto primitives
- Include test vectors documentation
- `TF-01`: encrypt → decrypt same file → plaintext identical
- `TF-02`: PRE delegation A→B: B decrypts, third party C cannot
