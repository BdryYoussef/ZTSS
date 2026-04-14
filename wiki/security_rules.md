# Security Rules (Zero-Trust)

## ES1 — Never Trust, Always Verify

- Every API request: **JWT RS256 (TTL ≤ 5 min) + PoP**
- No persistent sessions; stateless per-request auth
- See [[auth_requirements]]

## ES2 — Confidentiality at Rest

- **No node ever stores plaintext**
- Client-side encryption mandatory before any network send
- See [[crypto_layer#Secure Upload Flow]]

## ES3 — Confidentiality in Transit

- All inter-node channels: **TLS 1.3** or **NOISE Protocol**
- No exceptions; no fallback to cleartext
- See [[network_layer#Transport Security]]
- Verified by: `TS-01` (Wireshark capture)

## ES4 — Collusion Resistance

- System must remain confidential when **k−1 nodes are compromised**
- With k=3: any 2 compromised nodes → data still unreadable
- Verified by: `TS-04` (2/3 nodes compromised, no re-key → data illegible)
- Enforced by: [[crypto_layer#Proxy Re-Encryption]]

## ES5 — Auditability

- Every access → **signed + timestamped log entry**
- Format: `{ timestamp, action, sig }`
- Accessible at `GET /audit`
- Signatures prevent log tampering

## HTTP Error Codes (Security)

| Condition | HTTP Code |
|-----------|-----------|
| Expired/invalid JWT | 401 Unauthorized |
| Missing PoP | 403 Forbidden |
| Merkle integrity failure | reject + log alert |

## Full Adversarial Test Matrix

| ID | Attack | Procedure | Pass Criterion |
|----|--------|-----------|----------------|
| TS-01 | Eavesdropping | Wireshark on inter-node channel | No plaintext visible |
| TS-02 | Tampering | Modify 1 byte of stored chunk | Merkle reject + alert log |
| TS-03 | JWT Replay | Reuse JWT after expiry | HTTP 401 |
| TS-04 | Collusion | 2/3 nodes compromised, no re-key | Data unreadable |
| TS-05 | Missing PoP | Send JWT without PoP | HTTP 403 |
