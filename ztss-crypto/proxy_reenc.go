// Proxy Re-Encryption (PRE) for ZTSS.
//
// ── Security model ────────────────────────────────────────────────────────────
//
// The CDC mandates (wiki/crypto_layer.md §PRE):
//
//   rkA→B = ReKeyGen(SKA, PKB)        // computed by A only
//   CB    = ReEncrypt(rkA→B, CA)      // computed by proxy, no decryption
//   P     = Decrypt(SKB, CB)          // computed by B
//
//   "The proxy node cannot decrypt CA nor CB individually;
//    it holds neither SKA nor SKB."
//
// ── Why scalar-division PRE cannot be used directly ──────────────────────────
//
// The classic single-hop PRE scheme uses rkA→B = skA · skB⁻¹ (mod ℓ) so that
// the proxy can transform the capsule R → rkA→B·R, and Bob recovers SA by
// computing skB·(rkA→B·R) = SA.  This requires Alice to know skB — which she
// does not.  Alice only has skA (a scalar) and pkB (a compressed point = skB·G).
//
// ── Adopted scheme: ephemeral-DH key-wrapping (CPA-secure for honest proxy) ──
//
//   ReKeyGen(skA, pkB):
//     r_ek   ← CSPRNG (64 B → scalar, uniform mod ℓ)
//     R_ek    = r_ek · G               (ephemeral point; published to proxy)
//     K_ek    = r_ek · pkB             (DH: only Alice + Bob can compute this)
//     wKey‖wNonce = HKDF(K_ek,  info="ztss-pre-rekey-v1")
//     wSkA    = AES-256-GCM(wKey, wNonce, skA)   (32 B plaintext + 16 B tag = 48 B)
//     ReKey   = R_ek ‖ wSkA            (80 bytes total, held by proxy or stored)
//
//   ReEncrypt(rk, C_A):
//     C_B = rk ‖ C_A                   (proxy prepends the re-key header; O(1) work)
//
//   ReDecrypt(skB, C_B):
//     K_ek   = skB · R_ek              (skB·r_ek·G = r_ek·pkB  ✓ EC commutativity)
//     wKey‖wNonce = HKDF(K_ek, info="ztss-pre-rekey-v1")
//     skA    = AES-GCM-Open(wKey, wNonce, wSkA)
//     SA     = skA · R_capsule         (recover ECIES shared point)
//     eKey‖eNonce = HKDF(SA, info="ztss-ecies-v1")
//     P      = AES-GCM-Open(eKey, eNonce, payload)
//
// ── Why the proxy cannot decrypt ─────────────────────────────────────────────
//
//   The proxy holds: R_ek (point), wSkA (ciphertext), R_capsule (point), ct.
//
//   To unwrap wSkA it needs K_ek = r_ek·pkB.
//     • r_ek is Alice's ephemeral secret — discarded after ReKeyGen returns.
//     • pkB = skB·G; computing r_ek·pkB from R_ek = r_ek·G and pkB alone is the
//       EC Diffie-Hellman problem (computationally hard).
//     → The proxy cannot recover K_ek.
//
//   To compute SA = skA·R_capsule the proxy would need skA — which is inside the
//   ciphertext wSkA it cannot open.  It also cannot invert R_capsule = r·G
//   (discrete-log problem).
//     → The proxy cannot compute SA.
//
//   Without SA, the ECIES encKey and encNonce are pseudorandom and unknown;
//   the AES-GCM payload ct is computationally indistinguishable from random.
//     → The proxy cannot decrypt C_A or C_B.  ✓
//
// ── Wire formats ─────────────────────────────────────────────────────────────
//
//   ReKey  (80 bytes): [ R_ek:32B ][ wSkA:48B ]
//
//   Re-encrypted blob returned by ReEncrypt:
//     [ R_ek:32B ][ wSkA:48B ][ R_capsule:32B ][ AEAD_payload:N+16B ]
//     ^^^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//           PRE header (80B)          original ECIES ciphertext
package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"filippo.io/edwards25519"
)

// ── ReKey type ────────────────────────────────────────────────────────────────

// ReKey is the 80-byte re-encryption token produced by ReKeyGen.
//
//	Layout: [ R_ek : 32 B ][ wSkA : 48 B ]
//
//	R_ek  — Alice's ephemeral public key (r_ek·G).  Published to proxy.
//	wSkA  — AES-256-GCM encryption of skA under KDF(r_ek·pkB).  Proxy cannot
//	        open this without skB; Bob can open it with skB.
type ReKey [80]byte

const (
	rkEphOff  = 0  // byte offset of R_ek field
	rkEphLen  = 32 // byte length  of R_ek field
	rkWrapOff = 32 // byte offset of wSkA field
	rkWrapLen = 48 // byte length  of wSkA (32-byte skA + 16-byte GCM tag)
	rkLen     = 80 // total ReKey length

	// preHdrLen is the total byte length of the PRE header prepended by
	// ReEncrypt to the original ECIES ciphertext.
	preHdrLen = rkLen // 80 bytes
)

// ── ReKeyGen ──────────────────────────────────────────────────────────────────

// ReKeyGen computes the re-encryption token rkA→B from Alice's private key and
// Bob's public key.  Called only by Alice; the token is then given to the proxy.
//
// Alice discards r_ek after this call.  The proxy receives ReKey but cannot
// recover K_ek without skB (see package-level security argument above).
func ReKeyGen(skA PrivKey, pkB PubKey) (ReKey, error) {
	// Parse Bob's public key into a group point.
	pkBPt, err := parsePoint(pkB)
	if err != nil {
		return ReKey{}, fmt.Errorf("ztss/crypto: ReKeyGen: pkB: %w", err)
	}

	// Ephemeral scalar r_ek ← 64 random bytes reduced mod ℓ.
	seed := make([]byte, 64)
	if _, err = io.ReadFull(rand.Reader, seed); err != nil {
		return ReKey{}, fmt.Errorf("ztss/crypto: ReKeyGen: ephemeral seed: %w", err)
	}
	rEk, err := new(edwards25519.Scalar).SetUniformBytes(seed)
	if err != nil {
		return ReKey{}, fmt.Errorf("ztss/crypto: ReKeyGen: ephemeral scalar: %w", err)
	}

	// R_ek = r_ek·G  (published to proxy; safe).
	REk := new(edwards25519.Point).ScalarBaseMult(rEk)

	// K_ek = r_ek·pkB = r_ek·skB·G  (Alice computes; proxy cannot).
	KEk := new(edwards25519.Point).ScalarMult(rEk, pkBPt)

	// Derive wrap key+nonce from K_ek under domain-separated info string.
	wKey, wNonce, err := sharedKDF(KEk, infoPreRekey)
	if err != nil {
		return ReKey{}, fmt.Errorf("ztss/crypto: ReKeyGen: KDF: %w", err)
	}

	// Wrap skA under (wKey, wNonce) — 32 B plaintext → 48 B ciphertext+tag.
	wSkA, err := gcmSeal(wKey, wNonce, skA[:])
	if err != nil {
		return ReKey{}, fmt.Errorf("ztss/crypto: ReKeyGen: wrap skA: %w", err)
	}
	if len(wSkA) != rkWrapLen {
		// Invariant: AES-GCM on 32-byte input always produces exactly 48 bytes.
		return ReKey{}, errors.New("ztss/crypto: ReKeyGen: internal: unexpected wrap length")
	}

	var rk ReKey
	copy(rk[rkEphOff:], REk.Bytes()) // 32 bytes
	copy(rk[rkWrapOff:], wSkA)       // 48 bytes
	return rk, nil
}

// ── ReEncrypt ─────────────────────────────────────────────────────────────────

// ReEncrypt is the proxy operation.  It prepends the 80-byte ReKey header to
// the original ECIES ciphertext (C_A) so that Bob can decrypt.
//
// The proxy performs no cryptographic computation on the payload — it is a
// pure concatenation.  The proxy cannot read or alter the content:
//   - The key material skA is inside wSkA which the proxy cannot open.
//   - The AES-GCM payload is authenticated; any bit-flip is detected by Bob.
//
// Input  ciphertext: ECIES wire format  [ R_capsule:32B ][ ct+tag:N+16B ]
// Output re-enc blob: [ R_ek:32B ][ wSkA:48B ][ R_capsule:32B ][ ct+tag:N+16B ]
func ReEncrypt(rk ReKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < eciesHdrLen+16 {
		return nil, errors.New("ztss/crypto: ReEncrypt: ciphertext too short")
	}

	out := make([]byte, preHdrLen+len(ciphertext))
	copy(out[:preHdrLen], rk[:])
	copy(out[preHdrLen:], ciphertext)
	return out, nil
}

// ── ReDecrypt ─────────────────────────────────────────────────────────────────

// ReDecrypt decrypts a re-encrypted blob using Bob's private key skB.
//
// This implements the final step of the PRE triple:
//
//	P = Decrypt(SKB, CB)    (wiki/crypto_layer.md §PRE)
//
// Protocol (see package comment for full derivation):
//
//  1. Parse R_ek and wSkA from the 80-byte PRE header.
//  2. K_ek = skB·R_ek  → same point Alice computed as r_ek·pkB.
//  3. wKey‖wNonce = HKDF(K_ek, "ztss-pre-rekey-v1").
//  4. skA = AES-GCM-Open(wKey, wNonce, wSkA).
//  5. Parse R_capsule from the embedded ECIES header.
//  6. SA = skA·R_capsule  = skA·r·G   (Alice's original ECIES shared point).
//  7. encKey‖encNonce = HKDF(SA, "ztss-ecies-v1").
//  8. plaintext = AES-GCM-Open(encKey, encNonce, payload).
func ReDecrypt(skB PrivKey, reEncBlob []byte) ([]byte, error) {
	minLen := preHdrLen + eciesHdrLen + 16
	if len(reEncBlob) < minLen {
		return nil, errors.New("ztss/crypto: ReDecrypt: blob too short")
	}

	// ── Step 1: parse PRE header ──────────────────────────────────────────────
	var rEkBytes [32]byte
	copy(rEkBytes[:], reEncBlob[rkEphOff:rkEphOff+rkEphLen])
	wSkA := reEncBlob[rkWrapOff : rkWrapOff+rkWrapLen]
	eciesBlob := reEncBlob[preHdrLen:]

	// ── Step 2: K_ek = skB·R_ek ──────────────────────────────────────────────
	skBSc, err := parseScalar(skB)
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: ReDecrypt: skB: %w", err)
	}
	REk, err := parsePoint(rEkBytes)
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: ReDecrypt: R_ek: %w", err)
	}
	KEk := new(edwards25519.Point).ScalarMult(skBSc, REk)

	// ── Step 3: wrap key derivation ───────────────────────────────────────────
	wKey, wNonce, err := sharedKDF(KEk, infoPreRekey)
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: ReDecrypt: wrap KDF: %w", err)
	}

	// ── Step 4: recover skA ───────────────────────────────────────────────────
	skABytes, err := gcmOpen(wKey, wNonce, wSkA)
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: ReDecrypt: unwrap skA: %w", err)
	}
	if len(skABytes) != 32 {
		return nil, errors.New("ztss/crypto: ReDecrypt: unwrapped skA has wrong length")
	}
	var skAArr [32]byte
	copy(skAArr[:], skABytes)
	skASc, err := parseScalar(skAArr)
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: ReDecrypt: recovered skA invalid: %w", err)
	}

	// ── Step 5: parse R_capsule from embedded ECIES blob ─────────────────────
	if len(eciesBlob) < eciesHdrLen+16 {
		return nil, errors.New("ztss/crypto: ReDecrypt: embedded ECIES blob too short")
	}
	var rCapBytes [32]byte
	copy(rCapBytes[:], eciesBlob[:32])
	RCap, err := parsePoint(rCapBytes)
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: ReDecrypt: capsule R: %w", err)
	}

	// ── Step 6: SA = skA·R_capsule ────────────────────────────────────────────
	// Correctness: ECIESEncrypt computed SA = r·pkA = r·skA·G.
	//              ReDecrypt   computes SA = skA·(r·G) = skA·r·G  ✓
	SA := new(edwards25519.Point).ScalarMult(skASc, RCap)

	// ── Steps 7–8: ECIES key derivation + decryption ─────────────────────────
	encKey, encNonce, err := sharedKDF(SA, infoECIES)
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: ReDecrypt: ECIES KDF: %w", err)
	}
	return gcmOpen(encKey, encNonce, eciesBlob[eciesHdrLen:])
}
