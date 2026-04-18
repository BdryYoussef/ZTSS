# ZTSS Live Demo Script

> **Project directory:** `/media/youssef/SATA/ZTSS/ZTSS`  
> **API address:** `http://localhost:8090`  
> **Estimated time:** ~4 minutes end-to-end

---

## Before the Demo — One-Time Setup

Run this **once** before you start recording or presenting. It resets everything to a clean state.

```bash
cd /media/youssef/SATA/ZTSS/ZTSS

# Tear down any old containers and volumes
docker compose down -v

# Rebuild and start the 4-node cluster
docker compose up --build -d

# Wait ~5 seconds for nodes to boot, then confirm they are up
sleep 5
docker compose ps
```

**Expected output:** 4 containers all showing `Up` with ports `0.0.0.0:8090->8080/tcp`.

> ⚠️ The `(unhealthy)` label is a Docker health-check detail — the API is fully functional. You can ignore it or mention it is a monitoring probe, not a failure.

---

## Step 1 — Show the cluster is running

```bash
docker compose ps
```

**Say:** *"We have a 4-node cluster. Node 1 is the entry point, exposed on port 8090. The other three nodes handle P2P replication."*

---

## Step 2 — Show the audit log is empty (clean state)

```bash
curl -s http://localhost:8090/audit
```

**Expected:** `[]`

**Say:** *"The audit log is empty — nothing has been stored yet. Every operation will be recorded here with a cryptographic signature."*

---

## Step 3 — Create a demo file

```bash
echo "This is a top-secret document from Alice." > demo_secret.txt
cat demo_secret.txt
```

**Say:** *"This is Alice's plaintext. It never leaves her machine unencrypted."*

---

## Step 4 — Alice uploads the file

```bash
python3 ztss_client.py upload demo_secret.txt
```

**Expected output:**
```
[upload] read 42 bytes from 'demo_secret.txt'
[upload] 1 chunk(s), ciphertext = 70 bytes
[upload] root_cid = <64-char hex>
✅ Registered — identity_id: <id>
✅ Token acquired — expires in 300 s
✅ Uploaded — root_cid: <64-char hex>, chunks_count: 1

=== Upload complete ===
{
  "root_cid":     "<64-char hex>",
  "chunks_count": 1,
  "key_hex":      "<64-char hex>",
  "nonce_hex":    "<24-char hex>"
}
[!] Save key_hex — pass it to the download command via --key.
```

**Say:** *"Alice registers an Ed25519 identity key, gets a short-lived RS256 JWT, then uploads. The server only ever receives AES-256-GCM ciphertext — it has no idea what the file contains."*

> 📋 **Copy the `root_cid` and `key_hex` values** — you need them in Step 6.

---

## Step 5 — Show the audit log has the upload entry

```bash
curl -s http://localhost:8090/audit
```

**Expected:** a JSON array with one entry showing `POST /upload`, the identity ID, status 201, and a signature.

**Say:** *"The audit log now has a tamper-evident entry. The `sig` field is an Ed25519 signature over the log entry — anyone can verify it with Alice's public key."*

---

## Step 6 — Bob downloads and decrypts

Paste the `root_cid` and `key_hex` from Step 4:

```bash
python3 ztss_client.py download \
  <root_cid> \
  recovered_secret.txt \
  --key <key_hex>
```

**Expected output:**
```
[download] root_cid  = <64-char hex>
[download] output    = recovered_secret.txt
✅ Registered — identity_id: <bob's id>
✅ Token acquired — expires in 300 s
- Downloaded 1 chunk(s), ciphertext blob = 70 bytes
- Stripping 12-byte nonce prefix + 16-byte GCM tag (PRE simulation)…
- ✅ Decrypted — recovered 42 bytes plaintext

=== Download complete ===
Wrote 42 bytes → /media/youssef/SATA/ZTSS/ZTSS/recovered_secret.txt
```

**Say:** *"Bob registers his own independent identity. He fetches the encrypted chunks, strips the nonce and the GCM authentication tag, and recovers the plaintext locally. The server never decrypts anything."*

---

## Step 7 — Verify the files are identical

```bash
diff demo_secret.txt recovered_secret.txt && echo "✅ Files are identical"
cat recovered_secret.txt
```

**Expected:** `✅ Files are identical` and the original plaintext printed.

**Say:** *"Byte-for-byte identical. The full zero-trust upload/download cycle is complete."*

---

## Step 8 — Show the audit log again (both entries)

```bash
curl -s http://localhost:8090/audit | python3 -m json.tool
```

**Say:** *"The audit log now has two signed entries — Alice's upload and Bob's download — each with a timestamp and a cryptographic signature. Nothing can be deleted or altered without invalidating the signatures."*

---

## Talking Points (if teacher asks questions)

| Question | Answer |
|---|---|
| *Why doesn't the server decrypt?* | ES2 security rule: the server is a dumb byte store. Encryption and decryption are purely client-side. |
| *What is the JWT for?* | Identity authentication. RS256, 300-second TTL. A replayed JWT is rejected (jti replay check). |
| *What is the PoP header?* | Proof-of-Possession. Every request carries an EdDSA signature over a fresh challenge, proving the caller holds the private key — not just a stolen token. |
| *What is the Merkle root?* | The `root_cid` is a binary Merkle tree root over all chunk SHA-256 hashes. It acts as a tamper-evident file descriptor — any corruption in a chunk changes the root. |
| *Why 4 nodes?* | P2P replication. Node 1 is the API gateway. Nodes 2–4 replicate chunks for availability. |
| *What is PRE?* | Proxy Re-Encryption. In production, Alice would re-encrypt the file key with Bob's public key using the `POST /share` endpoint. The `--key` flag in the demo simulates out-of-band key delivery. |

---

## Reset Between Runs

```bash
docker compose down -v && docker compose up --build -d && sleep 5
```

This wipes all stored chunks and the audit log, giving a clean slate.
