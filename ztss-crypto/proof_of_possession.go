// proof_of_possession.go — EdDSA Proof-of-Possession for ZTSS Zero-Trust auth.
//
// ── Role in the Zero-Trust stack ─────────────────────────────────────────────
//
//   wiki/auth_requirements.md §PoP:
//     "Scheme: EdDSA signature over server-issued challenge.
//      Required: alongside JWT on every request.
//      Missing PoP → HTTP 403 Forbidden."
//
//   wiki/security_rules.md §ES1:
//     "Every API request: JWT RS256 (TTL ≤ 5 min) + PoP"
//
// ── Key separation ────────────────────────────────────────────────────────────
//
// This file defines a second, independent key type family (IdentityPrivKey /
// IdentityPubKey / Signature) that is DISTINCT from the PrivKey / PubKey types
// in ecies.go.  Separation is mandatory:
//
//   • ecies.go  PrivKey  — raw Ed25519 group scalar, used for ECDH and PRE.
//     These keys must NOT be clamped and are not directly usable with the
//     crypto/ed25519 signing API, which expects a seed-derived key with
//     co-factor/clamping applied internally.
//
//   • This file IdentityPrivKey — a standard Ed25519 seed (32 bytes) compatible
//     with crypto/ed25519.  The signing machinery (SHA-512 pre-hashing, cofactor
//     clearing, nonce derivation from seed ‖ message) is handled by the stdlib.
//
// Never cross-use keys across roles.
//
// ── Challenge binding ─────────────────────────────────────────────────────────
//
// A raw EdDSA signature over an arbitrary challenge byte string is susceptible
// to cross-protocol attacks: a malicious server could present a crafted JWT
// header+payload as the "challenge" and coerce the client into signing it.
//
// To prevent this, ProofOfPossession prepends a fixed context string before
// signing:
//
//   signed_message = "ztss-pop-v1\x00" || challenge
//
// The '\x00' byte after the context string acts as a length separator,
// ensuring "ztss-pop-v1<suffix>" ≠ "ztss-pop-v1\x00<suffix>".
// VerifyPoP applies the same prefix before calling ed25519.Verify.
//
// ── Wire formats ─────────────────────────────────────────────────────────────
//
//   IdentityPrivKey [32]byte  — Ed25519 seed (never transmit)
//   IdentityPubKey  [32]byte  — Ed25519 public key (register with server)
//   Signature       [64]byte  — Ed25519 signature (sent in X-ZTSS-PoP header)
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// IdentityPrivKey is the 32-byte Ed25519 seed for the client's identity key.
// Kept secret on the client; never transmitted.  Generate with GenerateIdentityKey.
type IdentityPrivKey [32]byte

// IdentityPubKey is the 32-byte Ed25519 public key derived from an IdentityPrivKey.
// Registered with the ZTSS API server via POST /auth/register.
type IdentityPubKey [32]byte

// Signature is the 64-byte Ed25519 signature produced by ProofOfPossession.
// Transmitted on every API request to satisfy the PoP requirement (ES1).
type Signature [64]byte

// popContext is the mandatory domain-separation prefix prepended to every
// challenge before signing/verifying.  This prevents cross-protocol misuse:
// no valid PoP signature can be obtained by tricking the client into signing
// an arbitrary message without this prefix.
const popContext = "ztss-pop-v1\x00"

// ── Identity key generation ───────────────────────────────────────────────────

// GenerateIdentityKey generates a fresh Ed25519 identity key pair for use in
// Proof-of-Possession authentication.
//
// The key pair is separate from the ECIES/PRE keys (PrivKey / PubKey):
//   - IdentityPrivKey holds the raw 32-byte seed (not the 64-byte signing key).
//   - The full signing key is reconstructed on demand inside ProofOfPossession
//     via ed25519.NewKeyFromSeed, which applies SHA-512 pre-hashing and clamping
//     in accordance with RFC 8032 §5.1.
//
// The IdentityPubKey is the value sent to POST /auth/register.
func GenerateIdentityKey() (IdentityPrivKey, IdentityPubKey, error) {
	seed := make([]byte, ed25519.SeedSize) // 32 bytes
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return IdentityPrivKey{}, IdentityPubKey{}, fmt.Errorf("ztss/crypto: GenerateIdentityKey: %w", err)
	}

	signingKey := ed25519.NewKeyFromSeed(seed)
	rawPub := signingKey.Public().(ed25519.PublicKey)

	var sk IdentityPrivKey
	var pk IdentityPubKey
	copy(sk[:], seed)
	copy(pk[:], rawPub)
	return sk, pk, nil
}

// IdentityPubKeyFromPriv derives the IdentityPubKey from an IdentityPrivKey.
// Useful to reconstruct the public key from a stored seed without re-invoking
// GenerateIdentityKey.
func IdentityPubKeyFromPriv(sk IdentityPrivKey) IdentityPubKey {
	signingKey := ed25519.NewKeyFromSeed(sk[:])
	rawPub := signingKey.Public().(ed25519.PublicKey)
	var pk IdentityPubKey
	copy(pk[:], rawPub)
	return pk
}

// ── Proof-of-Possession ───────────────────────────────────────────────────────

// ProofOfPossession signs a server-issued challenge with the client's identity
// private key, producing a 64-byte Ed25519 signature.
//
// This function implements the interface mandated by wiki/crypto_layer.md:
//
//	func ProofOfPossession(sk PrivKey, challenge []byte) Signature
//
// NOTE: the wiki signature uses the generic PrivKey alias; the implementation
// accepts IdentityPrivKey to enforce key-role separation at compile time.
// The API layer maps between the two before calling this function.
//
// Signed payload (domain-separated):
//
//	signed_message = []byte("ztss-pop-v1\x00") || challenge
//
// The challenge MUST be a fresh, server-generated random value (≥ 16 bytes
// recommended) to prevent replay attacks (TS-03, TS-05).
func ProofOfPossession(sk IdentityPrivKey, challenge []byte) (Signature, error) {
	if len(challenge) == 0 {
		return Signature{}, errors.New("ztss/crypto: ProofOfPossession: challenge must not be empty")
	}

	signingKey := ed25519.NewKeyFromSeed(sk[:])
	msg := popMessage(challenge)

	rawSig := ed25519.Sign(signingKey, msg)

	var sig Signature
	copy(sig[:], rawSig)
	return sig, nil
}

// VerifyPoP verifies a Proof-of-Possession signature against a known public key
// and the original challenge.
//
// Returns nil if and only if:
//   - sig is a valid Ed25519 signature
//   - the signature covers popContext ‖ challenge  (not just challenge alone)
//   - the signature was produced by the holder of the private key behind pk
//
// Called by the API server middleware to enforce ES1 on every request.
// Missing or invalid PoP must be rejected with HTTP 403 (wiki/auth_requirements.md §PoP).
func VerifyPoP(pk IdentityPubKey, challenge []byte, sig Signature) error {
	if len(challenge) == 0 {
		return errors.New("ztss/crypto: VerifyPoP: challenge must not be empty")
	}

	msg := popMessage(challenge)
	if !ed25519.Verify(pk[:], msg, sig[:]) {
		return errors.New("ztss/crypto: VerifyPoP: signature verification failed")
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// popMessage constructs the domain-separated message that is signed and verified.
// Defined as a single function so sign and verify paths are guaranteed identical.
func popMessage(challenge []byte) []byte {
	prefix := []byte(popContext)
	msg := make([]byte, len(prefix)+len(challenge))
	copy(msg, prefix)
	copy(msg[len(prefix):], challenge)
	return msg
}
