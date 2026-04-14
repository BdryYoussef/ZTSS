"""
ztss_client.py — ZTSS demo client (used from demo.ipynb).

Implements the full Secure Upload Flow (wiki/crypto_layer.md §Secure Upload Flow):

  Step 1  Kfile ← CSPRNG(256 bits)            per-file symmetric key
  Step 2  C ← AES-256-GCM(Kfile, plaintext)   client-side encryption (ES2)
  Step 3  Split C into 256 KB chunks           SHA-256(chunkᵢ) = Hᵢ  (CID)
  Step 4  R = MerkleRoot(H₁ … Hₙ)             file descriptor / root_cid
  Step 5  POST /auth/register                  publish Ed25519 identity key
          GET  /auth/challenge → sign → POST /auth/token   get RS256 JWT
          POST /upload with Bearer JWT + X-ZTSS-PoP headers
  Step 6  Log Kenc = ECIES(PK_dest, Kfile)     (key wrap; shown but not sent)

Auth flow (wiki/auth_requirements.md):
  - JWT: RS256, TTL = 300 s  → Authorization: Bearer <token>
  - PoP: EdDSA sig over fresh challenge → X-ZTSS-PoP + X-ZTSS-Challenge

Dependencies (pure-Python, no native extensions required):
  pip install cryptography requests

All crypto is done client-side before any data leaves the process (ES2).
The server only ever receives opaque ciphertext chunks.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import List, Tuple

# ── Optional pretty output (jupyter / terminal) ───────────────────────────────
try:
    from IPython.display import display, Markdown  # type: ignore
    _IN_NOTEBOOK = True
except ImportError:
    _IN_NOTEBOOK = False

def _print(msg: str) -> None:
    if _IN_NOTEBOOK:
        display(Markdown(msg))
    else:
        print(msg, flush=True)

# ── Dependencies ──────────────────────────────────────────────────────────────
try:
    import requests
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption,
    )
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
except ImportError as exc:
    raise SystemExit(
        f"Missing dependency: {exc}\n"
        "Run:  pip install cryptography requests"
    )


# ─────────────────────────────────────────────────────────────────────────────
# §1  Crypto helpers
# ─────────────────────────────────────────────────────────────────────────────

CHUNK_SIZE   = 256 * 1024   # 256 KB  (wiki/storage_layer.md)
AES_KEY_SIZE = 32            # AES-256
NONCE_SIZE   = 12            # 96-bit GCM nonce
POP_CONTEXT  = b"ztss-pop-v1\x00"  # domain separator (proof_of_possession.go)


def random_bytes(n: int) -> bytes:
    """Cryptographically secure random bytes."""
    return os.urandom(n)


# ── AES-256-GCM ───────────────────────────────────────────────────────────────

def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """
    Step 2 — C ← AES-GCM(Kfile, plaintext, nonce)

    Returns (ciphertext_with_tag, nonce).
    The nonce is prepended to the ciphertext in the wire format used by
    ztss-crypto/aes_gcm.go: [nonce:12B][ciphertext+tag:N+16B].
    """
    assert len(key) == AES_KEY_SIZE, f"key must be {AES_KEY_SIZE} bytes"
    nonce = random_bytes(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)   # no AAD
    blob = nonce + ct                              # wire format: nonce‖ct‖tag
    return blob, nonce


def aes_gcm_decrypt(key: bytes, blob: bytes) -> bytes:
    """
    Decrypt an AES-GCM blob produced by aes_gcm_encrypt.
    blob = nonce(12) ‖ ciphertext+tag(N+16)
    """
    assert len(blob) > NONCE_SIZE + 16, "blob too short"
    nonce = blob[:NONCE_SIZE]
    ct    = blob[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ct, None)


# ── Chunking + SHA-256 CIDs ───────────────────────────────────────────────────

def chunk_data(data: bytes, chunk_size: int = CHUNK_SIZE) -> List[bytes]:
    """Step 3 — split data into fixed-size chunks."""
    if not data:
        return [b""]
    chunks = []
    for i in range(0, len(data), chunk_size):
        chunks.append(data[i : i + chunk_size])
    return chunks


def sha256_cid(chunk: bytes) -> bytes:
    """Compute SHA-256(chunk) → 32-byte CID."""
    return hashlib.sha256(chunk).digest()


# ── Merkle tree ───────────────────────────────────────────────────────────────

def merkle_root(cids: List[bytes]) -> bytes:
    """
    Step 4 — R = MerkleRoot(H₁ … Hₙ)

    Binary Merkle tree: pairwise SHA-256 with odd-node duplication, matching
    the algorithm in ztss-storage/merkle.go.
    """
    if not cids:
        return hashlib.sha256(b"").digest()
    layer = list(cids)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])    # duplicate last (odd-node rule)
        next_layer = []
        for i in range(0, len(layer), 2):
            combined = hashlib.sha256(layer[i] + layer[i + 1]).digest()
            next_layer.append(combined)
        layer = next_layer
    return layer[0]


# ── EdDSA identity key (PoP) ──────────────────────────────────────────────────

@dataclass
class IdentityKey:
    """
    Ed25519 identity key pair for Proof-of-Possession.

    Corresponds to ztss-crypto/proof_of_possession.go:
      IdentityPrivKey [32]byte  Ed25519 seed
      IdentityPubKey  [32]byte  Ed25519 public key
    """
    _priv: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "IdentityKey":
        return cls(Ed25519PrivateKey.generate())

    @property
    def public_bytes(self) -> bytes:
        """Raw 32-byte Ed25519 public key."""
        return self._priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def public_key_b64(self) -> str:
        """Base64url-encoded public key (no padding), as expected by /auth/register."""
        return _b64url(self.public_bytes)

    def sign_pop(self, challenge: bytes) -> bytes:
        """
        ProofOfPossession: sign (POP_CONTEXT ‖ challenge) with Ed25519.

        Matches the domain-separated construction in proof_of_possession.go:
          signed_message = "ztss-pop-v1\\x00" || challenge
        """
        msg = POP_CONTEXT + challenge
        return self._priv.sign(msg)     # 64-byte Ed25519 signature


# ─────────────────────────────────────────────────────────────────────────────
# §2  API client
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ZTSSClient:
    """
    ZTSS REST API client.

    Implements the full authenticated upload flow (wiki/api_auth_layer.md):
      POST /auth/register
      GET  /auth/challenge + POST /auth/token  →  RS256 JWT (TTL=300s)
      POST /upload  with JWT + EdDSA PoP headers
    """
    base_url: str                          # e.g. "http://localhost:8090"
    identity: IdentityKey = field(default_factory=IdentityKey.generate)
    _identity_id: str = field(default="", init=False)
    _token: str       = field(default="", init=False)
    _token_exp: float = field(default=0.0, init=False)
    _session: requests.Session = field(default_factory=requests.Session, init=False)

    # ── Registration ──────────────────────────────────────────────────────────

    def register(self) -> str:
        """
        POST /auth/register → stores Ed25519 public key, returns identity_id.

        wiki/auth_requirements.md §Identity Model:
          "POST /auth/register → stores public_key, returns identity_id"
        """
        payload = {"public_key": self.identity.public_key_b64}
        resp = self._post("/auth/register", payload)
        self._identity_id = resp["identity_id"]
        _print(f"✅ **Registered** — `identity_id`: `{self._identity_id}`")
        return self._identity_id

    # ── Token acquisition ─────────────────────────────────────────────────────

    def get_token(self) -> str:
        """
        Full token flow:
          1. GET /auth/challenge  →  { challenge_id, challenge }
          2. EdDSA sign (POP_CONTEXT ‖ challenge)
          3. POST /auth/token     →  { token, expires_in: 300 }

        wiki/auth_requirements.md §JWT: "Algorithm: RS256, TTL: ≤ 300 s"
        """
        # Step 1 — obtain fresh challenge.
        cr = self._get("/auth/challenge")
        challenge_id = cr["challenge_id"]
        challenge    = _b64url_decode(cr["challenge"])

        # Step 2 — EdDSA PoP over (POP_CONTEXT ‖ challenge).
        sig = self.identity.sign_pop(challenge)

        # Step 3 — exchange for JWT.
        payload = {
            "identity_id":   self._identity_id,
            "challenge_id":  challenge_id,
            "pop_signature": _b64url(sig),
        }
        resp = self._post("/auth/token", payload)
        self._token     = resp["token"]
        self._token_exp = time.time() + resp.get("expires_in", 300) - 10  # 10s margin
        _print(f"✅ **Token acquired** — expires in {resp.get('expires_in', 300)} s")
        return self._token

    def _ensure_token(self) -> str:
        """Return a valid token, re-acquiring if near expiry."""
        if not self._token or time.time() > self._token_exp:
            self.get_token()
        return self._token

    # ── Upload ────────────────────────────────────────────────────────────────

    def upload(
        self,
        ciphertext_blob: bytes,
        root_cid_hex: str,
        chunk_cids: List[bytes],
        chunks: List[bytes],
    ) -> dict:
        """
        POST /upload with:
          Authorization: Bearer <JWT>
          X-ZTSS-Challenge: <fresh challenge>
          X-ZTSS-PoP: <Ed25519 sig over (POP_CONTEXT ‖ challenge)>

        Body: { root_cid, chunks: [{ index, cid, data }…] }

        wiki/api_auth_layer.md §Upload:
          "Client-side encryption mandatory before any network send" (ES2)
        """
        token = self._ensure_token()

        # Fresh per-request PoP challenge (inline, not from /auth/challenge).
        challenge = random_bytes(32)
        pop_sig   = self.identity.sign_pop(challenge)

        headers = {
            "Authorization":    f"Bearer {token}",
            "X-ZTSS-Challenge": _b64url(challenge),
            "X-ZTSS-PoP":       _b64url(pop_sig),
            "Content-Type":     "application/json",
        }

        chunk_list = []
        for idx, (cid, chunk) in enumerate(zip(chunk_cids, chunks)):
            chunk_list.append({
                "index": idx,
                "cid":   cid.hex(),
                "data":  base64.b64encode(chunk).decode(),
            })

        body = {
            "root_cid": root_cid_hex,
            "chunks":   chunk_list,
        }

        resp = self._session.post(
            self.base_url + "/upload",
            headers=headers,
            data=json.dumps(body),
            timeout=30,
        )
        _raise_for_status(resp)
        result = resp.json()
        _print(
            f"✅ **Uploaded** — `root_cid`: `{result['root_cid']}`, "
            f"`chunks_count`: {result['chunks_count']}"
        )
        return result

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _get(self, path: str) -> dict:
        resp = self._session.get(self.base_url + path, timeout=10)
        _raise_for_status(resp)
        return resp.json()

    def _post(self, path: str, payload: dict) -> dict:
        resp = self._session.post(
            self.base_url + path,
            json=payload,
            timeout=10,
        )
        _raise_for_status(resp)
        return resp.json()


# ─────────────────────────────────────────────────────────────────────────────
# §3  Full demo flow
# ─────────────────────────────────────────────────────────────────────────────

def run_demo(
    base_url: str = "http://localhost:8090",
    plaintext: bytes | None = None,
) -> dict:
    """
    Execute the complete Secure Upload Flow and return a summary dict.

    Steps (wiki/crypto_layer.md §Secure Upload Flow):
      1  Generate Kfile ← CSPRNG(256 bits)
      2  C ← AES-256-GCM(Kfile, plaintext, nonce)
      3  Split C into 256 KB chunks; compute Hᵢ = SHA-256(chunkᵢ)
      4  Compute R = MerkleRoot(H₁ … Hₙ)
      5  Register → get JWT → POST /upload with JWT + EdDSA PoP
      6  Derive Kenc = HKDF(Kfile) [shown; would be ECIES-wrapped in prod]

    Args:
        base_url:  ZTSS API base URL (default: http://localhost:8090).
        plaintext: Raw bytes to encrypt.  Defaults to a 300 KB dummy payload
                   so the demo exercises multi-chunk splitting.

    Returns:
        dict with keys: root_cid, chunks_count, file_key_hex, nonce_hex
    """
    _print("# 🔐 ZTSS Secure Upload Demo\n")
    _print(f"**API base URL:** `{base_url}`\n")

    # ── Step 0: prepare plaintext ────────────────────────────────────────────
    if plaintext is None:
        # 300 KB — just over one 256 KB chunk → forces a two-chunk upload.
        plaintext = b"ZTSS-DEMO-PLAINTEXT " * (300 * 1024 // 20)
        plaintext = plaintext[:300 * 1024]
    plaintext_size = len(plaintext)
    _print(f"**Plaintext size:** {plaintext_size:,} bytes ({plaintext_size / 1024:.1f} KB)\n")

    # ── Step 1: Kfile ← CSPRNG(256) ─────────────────────────────────────────
    _print("## Step 1 — Generate per-file encryption key (Kfile)")
    kfile = random_bytes(AES_KEY_SIZE)
    _print(f"- `Kfile` (hex, first 8 bytes): `{kfile[:8].hex()}…` _(never transmitted)_\n")

    # ── Step 2: C ← AES-256-GCM(Kfile, plaintext) ───────────────────────────
    _print("## Step 2 — Encrypt with AES-256-GCM")
    ciphertext_blob, nonce = aes_gcm_encrypt(kfile, plaintext)
    _print(
        f"- Nonce (96-bit): `{nonce.hex()}`\n"
        f"- Ciphertext size: {len(ciphertext_blob):,} bytes "
        f"(= plaintext + 12 nonce + 16 GCM tag)\n"
    )

    # Verify round-trip locally before upload.
    recovered = aes_gcm_decrypt(kfile, ciphertext_blob)
    assert recovered == plaintext, "AES-GCM round-trip failed — BUG"
    _print("- ✅ Local AES-GCM round-trip verified\n")

    # ── Step 3: chunk + CIDs ─────────────────────────────────────────────────
    _print("## Step 3 — Split into 256 KB chunks, compute SHA-256 CIDs")
    chunks     = chunk_data(ciphertext_blob)
    chunk_cids = [sha256_cid(c) for c in chunks]
    _print(f"- **{len(chunks)} chunk(s)** produced:\n")
    for i, (cid, chunk) in enumerate(zip(chunk_cids, chunks)):
        _print(f"  - Chunk {i}: {len(chunk):,} bytes  CID=`{cid.hex()[:16]}…`")
    _print("")

    # ── Step 4: Merkle root ──────────────────────────────────────────────────
    _print("## Step 4 — Compute Merkle root (file descriptor)")
    root = merkle_root(chunk_cids)
    root_hex = root.hex()
    _print(f"- `root_cid` = `{root_hex}`\n")

    # ── Step 5: Auth + upload ────────────────────────────────────────────────
    _print("## Step 5 — Authenticate and upload (JWT RS256 + EdDSA PoP)")
    client = ZTSSClient(base_url=base_url)

    # 5a  Registration
    _print("### 5a — Register Ed25519 identity key")
    _print(f"- Public key (base64url): `{client.identity.public_key_b64[:24]}…`")
    client.register()

    # 5b  JWT token
    _print("\n### 5b — Obtain RS256 JWT (TTL = 300 s)")
    client.get_token()

    # 5c  Upload ciphertext chunks
    _print("\n### 5c — POST /upload")
    result = client.upload(
        ciphertext_blob=ciphertext_blob,
        root_cid_hex=root_hex,
        chunk_cids=chunk_cids,
        chunks=chunks,
    )

    # ── Step 6: Key wrapping (illustrative) ──────────────────────────────────
    _print("\n## Step 6 — Key encapsulation (ECIES/HKDF, illustrative)")
    # In production: Kenc = ECIES(PK_dest, Kfile)
    # Here we use HKDF to derive a wrapped key for illustration only.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ztss-demo-kenc-v1",
        backend=default_backend(),
    )
    kenc = hkdf.derive(kfile)
    _print(
        f"- `Kenc` (HKDF-derived demo, first 8 B): `{kenc[:8].hex()}…`\n"
        "- _(In production: Kenc = ECIES(PK_dest, Kfile) — Kfile never leaves the client)_\n"
    )

    # ── Summary ───────────────────────────────────────────────────────────────
    _print("---\n## ✅ Upload complete — Summary\n")
    summary = {
        "root_cid":      root_hex,
        "chunks_count":  len(chunks),
        "file_key_hex":  kfile.hex(),    # ← KEEP SECRET in production!
        "nonce_hex":     nonce.hex(),
        "identity_id":   client._identity_id,
        "plaintext_len": plaintext_size,
    }
    _print("| Field | Value |")
    _print("|---|---|")
    for k, v in summary.items():
        display_v = str(v)
        if len(display_v) > 40:
            display_v = display_v[:40] + "…"
        _print(f"| `{k}` | `{display_v}` |")
    return summary


# ─────────────────────────────────────────────────────────────────────────────
# §4  Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _b64url(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    """Base64url-decode, tolerating missing padding."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _raise_for_status(resp: requests.Response) -> None:
    """Raise a descriptive error for non-2xx responses."""
    if not resp.ok:
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        raise RuntimeError(
            f"API error {resp.status_code} {resp.reason} "
            f"on {resp.request.method} {resp.url}:\n{body}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# §5  CLI entry-point (optional — also importable from demo.ipynb)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ZTSS demo client")
    parser.add_argument(
        "--url",
        default="http://localhost:8090",
        help="ZTSS API base URL (default: http://localhost:8090)",
    )
    parser.add_argument(
        "--file",
        default=None,
        help="Path to a file to encrypt+upload (default: 300 KB synthetic payload)",
    )
    args = parser.parse_args()

    plaintext: bytes | None = None
    if args.file:
        with open(args.file, "rb") as fh:
            plaintext = fh.read()

    summary = run_demo(base_url=args.url, plaintext=plaintext)
    print("\n=== Summary ===")
    print(json.dumps(summary, indent=2))
