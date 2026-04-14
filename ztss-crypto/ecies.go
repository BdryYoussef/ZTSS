// Package crypto implements ZTSS cryptographic primitives:
// AES-256-GCM bulk encryption (aes_gcm.go), ECIES key encapsulation on the
// Ed25519 prime-order group (this file), and proxy re-encryption (proxy_reenc.go).
//
// Why Ed25519 and not raw X25519?
//
// X25519 clamps the three low bits and the top bit of every scalar before use,
// making the scalar set non-closed under addition and inversion.  PRE requires
// computing arbitrary scalar products across independent key pairs, which breaks
// under clamping.  The Ed25519 group (via filippo.io/edwards25519) exposes the
// full prime-order group of order ℓ = 2²⁵² + 27742317777372353535851937790883648493
// with canonical byte encoding, inversion, and unclamped scalar × point
// multiplication — all required by the re-encryption scheme in proxy_reenc.go.
//
// Dependency: filippo.io/edwards25519
//   go get filippo.io/edwards25519
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/hkdf"
)

// ── Public types ──────────────────────────────────────────────────────────────

// PrivKey is a 32-byte canonical little-endian Ed25519 scalar in [0, ℓ).
// Generate with GenerateKeyPair; never construct from a clamped X25519 scalar.
type PrivKey [32]byte

// PubKey is a 32-byte compressed Ed25519 point  (little-endian y with sign bit).
type PubKey [32]byte

// ── Constants ─────────────────────────────────────────────────────────────────

// eciesHdrLen is the byte length of the ephemeral-point header in every ECIES
// ciphertext: [ CapsuleR : 32 B ][ AES-GCM(payload+tag) : N+16 B ]
const eciesHdrLen = 32

// HKDF info strings — domain-separate every key derivation context.
const (
	infoECIES    = "ztss-ecies-v1"    // ECIES encapsulation key derivation
	infoPreRekey = "ztss-pre-rekey-v1" // PRE wrap-key derivation (proxy_reenc.go)
)

// ── Key generation ────────────────────────────────────────────────────────────

// GenerateKeyPair produces a fresh (PrivKey, PubKey) pair by sampling 64
// random bytes and reducing them mod ℓ (SetUniformBytes).  This yields a
// uniform distribution over the Ed25519 scalar field with no bias.
func GenerateKeyPair() (PrivKey, PubKey, error) {
	seed := make([]byte, 64)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return PrivKey{}, PubKey{}, fmt.Errorf("ztss/crypto: GenerateKeyPair: %w", err)
	}

	sc, err := new(edwards25519.Scalar).SetUniformBytes(seed)
	if err != nil {
		return PrivKey{}, PubKey{}, fmt.Errorf("ztss/crypto: GenerateKeyPair: scalar reduction: %w", err)
	}

	pt := new(edwards25519.Point).ScalarBaseMult(sc)

	var sk PrivKey
	var pk PubKey
	copy(sk[:], sc.Bytes())
	copy(pk[:], pt.Bytes())
	return sk, pk, nil
}

// ── Package-private helpers ───────────────────────────────────────────────────

// parseScalar decodes a PrivKey into an edwards25519.Scalar, rejecting any
// encoding that is not in canonical form (i.e. not reduced mod ℓ).
func parseScalar(b [32]byte) (*edwards25519.Scalar, error) {
	sc, err := new(edwards25519.Scalar).SetCanonicalBytes(b[:])
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: invalid scalar: %w", err)
	}
	return sc, nil
}

// parsePoint decodes a PubKey into an edwards25519.Point, rejecting points not
// on the curve or not in the prime-order subgroup.
func parsePoint(b [32]byte) (*edwards25519.Point, error) {
	pt, err := new(edwards25519.Point).SetBytes(b[:])
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: invalid point: %w", err)
	}
	return pt, nil
}

// sharedKDF derives a 32-byte AES-256 key and a 12-byte GCM nonce from an
// Edwards25519 shared point via HKDF-SHA256.
//
//	IKM  = sharedPt.Bytes()  (32-byte compressed point)
//	salt = nil
//	info = caller-supplied domain-separation string
//	OKM  = key(32B) || nonce(12B)
func sharedKDF(sharedPt *edwards25519.Point, info string) (key, nonce []byte, err error) {
	r := hkdf.New(sha256.New, sharedPt.Bytes(), nil, []byte(info))
	buf := make([]byte, 32+12)
	if _, err = io.ReadFull(r, buf); err != nil {
		return nil, nil, fmt.Errorf("ztss/crypto: sharedKDF(%q): %w", info, err)
	}
	return buf[:32], buf[32:], nil
}

// gcmSeal encrypts plaintext with AES-256-GCM using a pre-derived key+nonce.
// Returns ciphertext ‖ tag (len = len(plaintext)+16).
// Used by ECIES and PRE so that the nonce is bound to the KDF output rather
// than being chosen independently.
func gcmSeal(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: gcmSeal: AES init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: gcmSeal: GCM init: %w", err)
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

// gcmOpen authenticates and decrypts AES-256-GCM ciphertext (ct ‖ tag).
// On tag mismatch the call returns ErrAuthFailed — no partial plaintext escapes.
func gcmOpen(key, nonce, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: gcmOpen: AES init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: gcmOpen: GCM init: %w", err)
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}
	return pt, nil
}

// ── ECIES ─────────────────────────────────────────────────────────────────────

// ECIESEncrypt encrypts plaintext for the holder of pk using ECIES on Ed25519.
//
// Protocol:
//
//  1. r  ← 64 random bytes → SetUniformBytes → canonical scalar
//  2. R   = r·G                  (ephemeral public key / capsule)
//  3. SA  = r·pk                 (ECDH shared point; only pk-holder can recompute)
//  4. key‖nonce = HKDF-SHA256(SA.Bytes(), info="ztss-ecies-v1")
//  5. ct  = AES-256-GCM(key, nonce, plaintext)   (includes 16-byte GCM tag)
//
// Wire format: [ R : 32 B ][ ct+tag : N+16 B ]
//
// The shared point SA is destroyed after key derivation; the ephemeral scalar r
// is never stored.  Decryption requires the private key corresponding to pk.
func ECIESEncrypt(pk PubKey, plaintext []byte) ([]byte, error) {
	pkPt, err := parsePoint(pk)
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: ECIESEncrypt: %w", err)
	}

	// Ephemeral scalar r.
	seed := make([]byte, 64)
	if _, err = io.ReadFull(rand.Reader, seed); err != nil {
		return nil, fmt.Errorf("ztss/crypto: ECIESEncrypt: ephemeral seed: %w", err)
	}
	r, err := new(edwards25519.Scalar).SetUniformBytes(seed)
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: ECIESEncrypt: ephemeral scalar: %w", err)
	}

	R := new(edwards25519.Point).ScalarBaseMult(r)   // capsule
	SA := new(edwards25519.Point).ScalarMult(r, pkPt) // shared point

	encKey, encNonce, err := sharedKDF(SA, infoECIES)
	if err != nil {
		return nil, err
	}

	ct, err := gcmSeal(encKey, encNonce, plaintext)
	if err != nil {
		return nil, err
	}

	out := make([]byte, eciesHdrLen+len(ct))
	copy(out[:32], R.Bytes())
	copy(out[32:], ct)
	return out, nil
}

// ECIESDecrypt decrypts a ciphertext produced by ECIESEncrypt, using sk.
//
// Shared-point recovery:
//
//	SA = sk·R   (sk × ephemeral-pubkey in capsule)
//
// Because R = r·G and pk = sk·G, we have:
//
//	Encrypt: SA = r·(sk·G) = r·sk·G
//	Decrypt: SA = sk·(r·G) = sk·r·G   ✓  (EC scalar mult is commutative)
//
// The same HKDF invocation then reproduces the exact encKey and nonce used
// during encryption, and gcmOpen verifies the GCM tag before returning any
// plaintext bytes.
func ECIESDecrypt(sk PrivKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < eciesHdrLen+16 {
		return nil, errors.New("ztss/crypto: ECIESDecrypt: ciphertext too short")
	}

	skSc, err := parseScalar(sk)
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: ECIESDecrypt: %w", err)
	}

	var rBytes [32]byte
	copy(rBytes[:], ciphertext[:32])
	R, err := parsePoint(rBytes)
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: ECIESDecrypt: invalid capsule: %w", err)
	}

	SA := new(edwards25519.Point).ScalarMult(skSc, R) // sk·R = SA

	encKey, encNonce, err := sharedKDF(SA, infoECIES)
	if err != nil {
		return nil, err
	}

	return gcmOpen(encKey, encNonce, ciphertext[eciesHdrLen:])
}
