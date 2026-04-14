// Package crypto implements ZTSS cryptographic primitives.
//
// Security constraints (from wiki/security_rules.md):
//   - ES2: no plaintext ever leaves the client; encryption is client-side only.
//   - 96-bit (12-byte) random nonce per encryption (NIST SP 800-38D §8.2.1).
//   - 256-bit AES key derived via HKDF-SHA256 from the caller-supplied key
//     material, binding the sub-key to a fixed "ztss-aes-gcm" info string.
//
// Interfaces (from wiki/crypto_layer.md):
//
//	func EncryptFile(plaintext []byte, key []byte) (ciphertext []byte, nonce []byte, err error)
//	func DecryptFile(ciphertext, nonce, key []byte) ([]byte, error)
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// nonceSize is 96 bits as mandated by the CDC and NIST SP 800-38D.
	nonceSize = 12

	// keySize is 256 bits (AES-256).
	keySize = 32

	// hkdfInfo binds the derived sub-key to this specific usage context.
	hkdfInfo = "ztss-aes-gcm-v1"
)

// deriveKey derives a 256-bit AES sub-key from keyMaterial using HKDF-SHA256.
// The nonce is used as the HKDF salt so that each (key, nonce) pair yields a
// unique sub-key, providing key commitment and domain separation.
func deriveKey(keyMaterial, salt []byte) ([]byte, error) {
	if len(keyMaterial) == 0 {
		return nil, errors.New("ztss/crypto: key material must not be empty")
	}

	r := hkdf.New(sha256.New, keyMaterial, salt, []byte(hkdfInfo))

	subKey := make([]byte, keySize)
	if _, err := io.ReadFull(r, subKey); err != nil {
		return nil, fmt.Errorf("ztss/crypto: HKDF expansion failed: %w", err)
	}

	return subKey, nil
}

// EncryptFile encrypts plaintext with AES-256-GCM.
//
//   - key: raw key material (any length ≥ 1 byte; HKDF stretches/compresses
//     it to exactly 256 bits).  For the secure upload flow the caller supplies
//     Kfile ← CSPRNG(32) (see wiki/crypto_layer.md §Secure Upload Flow).
//   - A fresh 96-bit nonce is generated from crypto/rand for every call.
//   - The returned ciphertext already contains the GCM authentication tag
//     appended by the standard library (16 bytes at the tail).
//   - The nonce is returned separately so the caller can store/transmit it
//     alongside the ciphertext.
func EncryptFile(plaintext []byte, key []byte) (ciphertext []byte, nonce []byte, err error) {
	// 1. Generate a random 96-bit nonce.
	nonce = make([]byte, nonceSize)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("ztss/crypto: nonce generation failed: %w", err)
	}

	// 2. Derive a 256-bit AES sub-key; salt = nonce.
	subKey, err := deriveKey(key, nonce)
	if err != nil {
		return nil, nil, err
	}

	// 3. Construct AES-256-GCM cipher.
	block, err := aes.NewCipher(subKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ztss/crypto: AES cipher init failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("ztss/crypto: GCM init failed: %w", err)
	}

	// 4. Seal: output is ciphertext || tag (tag appended by the stdlib).
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nonce, nil
}

// DecryptFile decrypts and authenticates ciphertext produced by EncryptFile.
//
//   - ciphertext: the raw bytes returned by EncryptFile (ciphertext || 16-byte tag).
//   - nonce: the 96-bit value returned by EncryptFile.
//   - key: the same key material that was passed to EncryptFile.
//
// Returns ErrAuthFailed (wrapping cipher.ErrOpen) when the authentication tag
// does not verify, preventing any partially-decrypted output from reaching the
// caller (ES2 enforcement).
var ErrAuthFailed = errors.New("ztss/crypto: authentication failed — ciphertext is corrupt or tampered")

func DecryptFile(ciphertext, nonce, key []byte) ([]byte, error) {
	// Validate inputs before touching any crypto.
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("ztss/crypto: invalid nonce length %d, expected %d", len(nonce), nonceSize)
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("ztss/crypto: ciphertext must not be empty")
	}

	// 1. Re-derive the same 256-bit sub-key (salt = nonce, deterministic).
	subKey, err := deriveKey(key, nonce)
	if err != nil {
		return nil, err
	}

	// 2. Reconstruct AES-256-GCM cipher.
	block, err := aes.NewCipher(subKey)
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: AES cipher init failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ztss/crypto: GCM init failed: %w", err)
	}

	// 3. Open: verify tag and decrypt in one atomic step.
	//    cipher.ErrOpen is returned on authentication failure; we wrap it in our
	//    sentinel so callers can use errors.Is(err, crypto.ErrAuthFailed).
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}

	return plaintext, nil
}
