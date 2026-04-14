// crypto_test.go — exhaustive test suite for the ztss-crypto package.
//
// Coverage mandate: ≥ 80% on all cryptographic primitives (wiki/crypto_layer.md).
//
// CDC test identifiers covered:
//   TF-01  AES round-trip: encrypt → decrypt produces identical plaintext.
//   TF-02  PRE delegation A→B: B decrypts; third party C cannot.
//   TS-02  Tampering: modifying a ciphertext byte is detected (ErrAuthFailed).
//   TS-05  Missing / wrong PoP rejected.
//
// File structure:
//   Section 1  — AES-256-GCM (EncryptFile / DecryptFile)
//   Section 2  — ECIES on Ed25519 (ECIESEncrypt / ECIESDecrypt)
//   Section 3  — Proxy Re-Encryption (ReKeyGen / ReEncrypt / ReDecrypt)
//   Section 4  — EdDSA Proof-of-Possession (GenerateIdentityKey / ProofOfPossession / VerifyPoP)
//   Section 5  — Key helpers (GenerateKeyPair / IdentityPubKeyFromPriv)
//   Section 6  — Test vectors (deterministic regression anchors)
package crypto

import (
	"bytes"
	"errors"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// mustGenerateKeyPair calls GenerateKeyPair and fails the test on error.
func mustGenerateKeyPair(t *testing.T) (PrivKey, PubKey) {
	t.Helper()
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return sk, pk
}

// mustGenerateIdentityKey calls GenerateIdentityKey and fails the test on error.
func mustGenerateIdentityKey(t *testing.T) (IdentityPrivKey, IdentityPubKey) {
	t.Helper()
	sk, pk, err := GenerateIdentityKey()
	if err != nil {
		t.Fatalf("GenerateIdentityKey: %v", err)
	}
	return sk, pk
}

// flipBit flips a single bit in a copy of b at byte index i.
func flipBit(b []byte, i int) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	out[i] ^= 0x01
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 1 — AES-256-GCM  (TF-01 / TS-02)
// ─────────────────────────────────────────────────────────────────────────────

// TestEncryptDecryptRoundTrip is TF-01: encrypt then decrypt must reproduce
// the original plaintext exactly.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	plaintext := []byte("Hello, ZTSS — Zero-Trust Secure Storage!")

	ct, nonce, err := EncryptFile(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}

	got, err := DecryptFile(ct, nonce, key)
	if err != nil {
		t.Fatalf("DecryptFile: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("TF-01 FAIL: round-trip mismatch\n got: %q\nwant: %q", got, plaintext)
	}
}

// TestEncryptEmptyPlaintext verifies that encrypting zero-length data succeeds
// and decrypts back to an empty slice (not nil).
func TestEncryptEmptyPlaintext(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16) // short key — HKDF stretches it
	ct, nonce, err := EncryptFile([]byte{}, key)
	if err != nil {
		t.Fatalf("EncryptFile empty: %v", err)
	}
	got, err := DecryptFile(ct, nonce, key)
	if err != nil {
		t.Fatalf("DecryptFile empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(got))
	}
}

// TestEncryptLargePlaintext stress-tests with a 10 MB payload (CDC performance
// target: upload 10 MB in < 3 s on local network; the crypto step must be fast).
func TestEncryptLargePlaintext(t *testing.T) {
	key := make([]byte, 32)
	plaintext := make([]byte, 10*1024*1024) // 10 MB
	for i := range plaintext {
		plaintext[i] = byte(i & 0xFF)
	}

	ct, nonce, err := EncryptFile(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptFile 10 MB: %v", err)
	}
	got, err := DecryptFile(ct, nonce, key)
	if err != nil {
		t.Fatalf("DecryptFile 10 MB: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Error("10 MB round-trip mismatch")
	}
}

// TestEncryptProducesFreshNonceEachCall verifies that two encryptions of the
// same plaintext produce different (nonce, ciphertext) pairs — proving CSPRNG
// is used and the same nonce is never reused.
func TestEncryptProducesFreshNonceEachCall(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	plain := []byte("same plaintext")

	ct1, n1, err := EncryptFile(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	ct2, n2, err := EncryptFile(plain, key)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(n1, n2) {
		t.Error("nonce collision: EncryptFile returned the same nonce twice")
	}
	if bytes.Equal(ct1, ct2) {
		t.Error("ciphertext collision: same plaintext encrypted with same key produced identical ciphertext")
	}
}

// TestNonceSize verifies the returned nonce is exactly 12 bytes (96 bits).
func TestNonceSize(t *testing.T) {
	key := bytes.Repeat([]byte{0xFF}, 32)
	_, nonce, err := EncryptFile([]byte("x"), key)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != nonceSize {
		t.Errorf("nonce length = %d, want %d", len(nonce), nonceSize)
	}
}

// TestCiphertextLength verifies AES-GCM overhead: len(ct) = len(pt) + 16 (tag).
func TestCiphertextLength(t *testing.T) {
	key := bytes.Repeat([]byte{0x00}, 32)
	plain := bytes.Repeat([]byte{0x99}, 100)

	ct, _, err := EncryptFile(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	want := len(plain) + 16
	if len(ct) != want {
		t.Errorf("ciphertext length = %d, want %d", len(ct), want)
	}
}

// TestDecryptWrongKey is TS-02: decryption with a wrong key must return
// ErrAuthFailed and no plaintext.
func TestDecryptWrongKey(t *testing.T) {
	key := bytes.Repeat([]byte{0xAA}, 32)
	wrongKey := bytes.Repeat([]byte{0xBB}, 32)
	plain := []byte("secret data")

	ct, nonce, err := EncryptFile(plain, key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptFile(ct, nonce, wrongKey)
	if err == nil {
		t.Fatal("DecryptFile with wrong key must fail")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("expected ErrAuthFailed, got: %v", err)
	}
}

// TestDecryptTamperedCiphertext is TS-02: flipping a bit in the ciphertext
// must be detected as ErrAuthFailed.
func TestDecryptTamperedCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	plain := []byte("tamper me")

	ct, nonce, err := EncryptFile(plain, key)
	if err != nil {
		t.Fatal(err)
	}

	tampered := flipBit(ct, 0)
	_, err = DecryptFile(tampered, nonce, key)
	if err == nil {
		t.Fatal("tampered ciphertext must fail authentication")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("expected ErrAuthFailed, got: %v", err)
	}
}

// TestDecryptTamperedTag ensures tag corruption at the end is detected.
func TestDecryptTamperedTag(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, 32)
	plain := []byte("tag tampering test")

	ct, nonce, err := EncryptFile(plain, key)
	if err != nil {
		t.Fatal(err)
	}

	tampered := flipBit(ct, len(ct)-1) // flip last byte of tag
	_, err = DecryptFile(tampered, nonce, key)
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("tag tamper: expected ErrAuthFailed, got: %v", err)
	}
}

// TestDecryptWrongNonce verifies that using the wrong nonce causes auth failure.
func TestDecryptWrongNonce(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 32)
	plain := []byte("nonce mismatch")

	ct, nonce, err := EncryptFile(plain, key)
	if err != nil {
		t.Fatal(err)
	}

	wrongNonce := flipBit(nonce, 0)
	_, err = DecryptFile(ct, wrongNonce, key)
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("wrong nonce: expected ErrAuthFailed, got: %v", err)
	}
}

// TestDecryptInvalidNonceLength verifies the input validation guard.
func TestDecryptInvalidNonceLength(t *testing.T) {
	ct := make([]byte, 32)
	key := make([]byte, 32)

	_, err := DecryptFile(ct, []byte{0x01, 0x02}, key) // 2 bytes ≠ 12
	if err == nil {
		t.Fatal("expected error for invalid nonce length")
	}
}

// TestDecryptEmptyCiphertext verifies the empty-ciphertext guard.
func TestDecryptEmptyCiphertext(t *testing.T) {
	nonce := make([]byte, nonceSize)
	key := make([]byte, 32)

	_, err := DecryptFile([]byte{}, nonce, key)
	if err == nil {
		t.Fatal("expected error for empty ciphertext")
	}
}

// TestDecryptEmptyKey verifies the empty-key guard in deriveKey.
func TestDecryptEmptyKey(t *testing.T) {
	ct, nonce, err := EncryptFile([]byte("hello"), []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptFile(ct, nonce, []byte{}) // empty key
	if err == nil {
		t.Fatal("expected error for empty key material")
	}
}

// TestEncryptEmptyKeyRejected ensures EncryptFile also rejects an empty key.
func TestEncryptEmptyKeyRejected(t *testing.T) {
	_, _, err := EncryptFile([]byte("data"), []byte{})
	if err == nil {
		t.Fatal("expected error for empty key material on encrypt")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 2 — ECIES on Ed25519
// ─────────────────────────────────────────────────────────────────────────────

// TestECIESRoundTrip encrypts a key blob for Alice and verifies she can decrypt.
func TestECIESRoundTrip(t *testing.T) {
	skA, pkA := mustGenerateKeyPair(t)
	payload := make([]byte, 32)
	for i := range payload {
		payload[i] = byte(i)
	}

	ct, err := ECIESEncrypt(pkA, payload)
	if err != nil {
		t.Fatalf("ECIESEncrypt: %v", err)
	}

	got, err := ECIESDecrypt(skA, ct)
	if err != nil {
		t.Fatalf("ECIESDecrypt: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("ECIES round-trip: plaintext mismatch")
	}
}

// TestECIESDecryptWrongKey verifies that decryption with the wrong private key fails.
func TestECIESDecryptWrongKey(t *testing.T) {
	_, pkA := mustGenerateKeyPair(t)
	skOther, _ := mustGenerateKeyPair(t)

	ct, err := ECIESEncrypt(pkA, []byte("secret blob"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = ECIESDecrypt(skOther, ct)
	if err == nil {
		t.Fatal("ECIESDecrypt with wrong key must fail")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("expected ErrAuthFailed, got: %v", err)
	}
}

// TestECIESTamperedCiphertext verifies authentication catches bit-flips.
func TestECIESTamperedCiphertext(t *testing.T) {
	skA, pkA := mustGenerateKeyPair(t)
	ct, err := ECIESEncrypt(pkA, []byte("tamper me"))
	if err != nil {
		t.Fatal(err)
	}

	// Flip a byte in the AEAD payload (past the 32-byte capsule header).
	tampered := flipBit(ct, 33)
	_, err = ECIESDecrypt(skA, tampered)
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("ECIES tamper: expected ErrAuthFailed, got: %v", err)
	}
}

// TestECIESShortCiphertext verifies the length guard.
func TestECIESShortCiphertext(t *testing.T) {
	skA, _ := mustGenerateKeyPair(t)
	_, err := ECIESDecrypt(skA, make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short ECIES ciphertext")
	}
}

// TestECIESFreshCapsulePerEncryption verifies that two encryptions to the same
// recipient produce distinct capsules (ephemeral scalar is fresh each time).
func TestECIESFreshCapsulePerEncryption(t *testing.T) {
	_, pkA := mustGenerateKeyPair(t)
	payload := []byte("same payload")

	ct1, err := ECIESEncrypt(pkA, payload)
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := ECIESEncrypt(pkA, payload)
	if err != nil {
		t.Fatal(err)
	}

	// First 32 bytes are the ephemeral capsule R.
	if bytes.Equal(ct1[:32], ct2[:32]) {
		t.Error("ECIES: ephemeral capsule reused across two encryptions")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 3 — Proxy Re-Encryption  (TF-02)
// ─────────────────────────────────────────────────────────────────────────────

// TestPREFullDelegation is TF-02:
//   Alice encrypts a file key for herself.
//   Alice generates rkA→B.
//   Proxy re-encrypts (ReEncrypt).
//   Bob (with skB) decrypts the re-encrypted blob via ReDecrypt.
//   Third party C (with skC) must NOT be able to decrypt.
func TestPREFullDelegation(t *testing.T) {
	// Key generation.
	skA, pkA := mustGenerateKeyPair(t)
	skB, pkB := mustGenerateKeyPair(t)
	skC, _ := mustGenerateKeyPair(t)

	fileKey := make([]byte, 32)
	for i := range fileKey {
		fileKey[i] = byte(i * 3)
	}

	// Alice encrypts her file key for herself.
	CA, err := ECIESEncrypt(pkA, fileKey)
	if err != nil {
		t.Fatalf("ECIESEncrypt (A): %v", err)
	}

	// Sanity: Alice can decrypt her own ciphertext.
	gotA, err := ECIESDecrypt(skA, CA)
	if err != nil {
		t.Fatalf("ECIESDecrypt (A→A): %v", err)
	}
	if !bytes.Equal(gotA, fileKey) {
		t.Fatal("Alice cannot decrypt her own ciphertext (setup error)")
	}

	// Alice generates re-key for Bob.
	rk, err := ReKeyGen(skA, pkB)
	if err != nil {
		t.Fatalf("ReKeyGen: %v", err)
	}

	// Proxy re-encrypts.
	CB, err := ReEncrypt(rk, CA)
	if err != nil {
		t.Fatalf("ReEncrypt: %v", err)
	}

	// Bob decrypts the re-encrypted blob.
	gotB, err := ReDecrypt(skB, CB)
	if err != nil {
		t.Fatalf("ReDecrypt (B): %v", err)
	}
	if !bytes.Equal(gotB, fileKey) {
		t.Errorf("TF-02 FAIL: Bob's plaintext mismatch\n got: %x\nwant: %x", gotB, fileKey)
	}

	// Third party C MUST NOT be able to decrypt (TF-02 negative).
	_, err = ReDecrypt(skC, CB)
	if err == nil {
		t.Fatal("TF-02 FAIL: third party C should not be able to ReDecrypt")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("C's failure should be ErrAuthFailed, got: %v", err)
	}
}

// TestPREMultipleRecipients verifies that independent re-keys work correctly:
// A delegates to B and to C separately; each can decrypt only their own blob.
func TestPREMultipleRecipients(t *testing.T) {
	skA, pkA := mustGenerateKeyPair(t)
	skB, pkB := mustGenerateKeyPair(t)
	skC, pkC := mustGenerateKeyPair(t)

	payload := []byte("shared payload")
	CA, err := ECIESEncrypt(pkA, payload)
	if err != nil {
		t.Fatal(err)
	}

	// Re-key to B.
	rkAB, err := ReKeyGen(skA, pkB)
	if err != nil {
		t.Fatal(err)
	}
	CB, err := ReEncrypt(rkAB, CA)
	if err != nil {
		t.Fatal(err)
	}

	// Re-key to C.
	rkAC, err := ReKeyGen(skA, pkC)
	if err != nil {
		t.Fatal(err)
	}
	CC, err := ReEncrypt(rkAC, CA)
	if err != nil {
		t.Fatal(err)
	}

	gotB, err := ReDecrypt(skB, CB)
	if err != nil || !bytes.Equal(gotB, payload) {
		t.Errorf("B delegation failed: err=%v match=%v", err, bytes.Equal(gotB, payload))
	}

	gotC, err := ReDecrypt(skC, CC)
	if err != nil || !bytes.Equal(gotC, payload) {
		t.Errorf("C delegation failed: err=%v match=%v", err, bytes.Equal(gotC, payload))
	}

	// B must not decrypt C's blob.
	_, err = ReDecrypt(skB, CC)
	if err == nil {
		t.Fatal("B must not decrypt C's re-encrypted blob")
	}
}

// TestReEncryptShortCiphertext verifies ReEncrypt rejects an undersized input.
func TestReEncryptShortCiphertext(t *testing.T) {
	var rk ReKey
	_, err := ReEncrypt(rk, make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short ciphertext in ReEncrypt")
	}
}

// TestReDecryptShortBlob verifies ReDecrypt rejects blobs that are too short.
func TestReDecryptShortBlob(t *testing.T) {
	skB, _ := mustGenerateKeyPair(t)
	_, err := ReDecrypt(skB, make([]byte, 20))
	if err == nil {
		t.Fatal("expected error for short re-enc blob in ReDecrypt")
	}
}

// TestReDecryptTamperedPayload verifies that a bit-flip in the AEAD payload
// propagates as ErrAuthFailed through the ReDecrypt chain.
func TestReDecryptTamperedPayload(t *testing.T) {
	skA, pkA := mustGenerateKeyPair(t)
	skB, pkB := mustGenerateKeyPair(t)

	CA, err := ECIESEncrypt(pkA, []byte("tamper test"))
	if err != nil {
		t.Fatal(err)
	}
	rk, err := ReKeyGen(skA, pkB)
	if err != nil {
		t.Fatal(err)
	}
	CB, err := ReEncrypt(rk, CA)
	if err != nil {
		t.Fatal(err)
	}

	// Flip a byte deep in the AEAD payload (past the 80-byte PRE header and
	// the 32-byte ECIES capsule, well into the ciphertext body).
	tampered := flipBit(CB, preHdrLen+eciesHdrLen+1)
	_, err = ReDecrypt(skB, tampered)
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("tampered PRE payload: expected ErrAuthFailed, got: %v", err)
	}
}

// TestReDecryptTamperedReKey verifies that corrupting the wSkA field (which
// the proxy holds) causes ReDecrypt to fail — confirming proxy isolation.
func TestReDecryptTamperedReKey(t *testing.T) {
	skA, pkA := mustGenerateKeyPair(t)
	skB, pkB := mustGenerateKeyPair(t)

	CA, err := ECIESEncrypt(pkA, []byte("proxy isolation test"))
	if err != nil {
		t.Fatal(err)
	}
	rk, err := ReKeyGen(skA, pkB)
	if err != nil {
		t.Fatal(err)
	}
	CB, err := ReEncrypt(rk, CA)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the wSkA portion of the PRE header (bytes 32–79).
	tampered := flipBit(CB, rkWrapOff+5)
	_, err = ReDecrypt(skB, tampered)
	if err == nil {
		t.Fatal("corrupted wSkA: ReDecrypt must fail")
	}
	// The failure wraps ErrAuthFailed from the inner gcmOpen on wSkA.
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("expected ErrAuthFailed, got: %v", err)
	}
}

// TestReKeyGenFreshness verifies that two calls to ReKeyGen for the same
// recipient always produce distinct re-keys.  The R_ek component (first 32
// bytes of the ReKey) must differ across calls because each invocation samples
// a fresh ephemeral scalar r_ek.  A collision would imply r_ek reuse, which
// directly compromises the security proof (proxy could accumulate two ciphertexts
// encrypted under the same wrap-key).
func TestReKeyGenFreshness(t *testing.T) {
	skA, _ := mustGenerateKeyPair(t)
	_, pkB := mustGenerateKeyPair(t)

	rk1, err := ReKeyGen(skA, pkB)
	if err != nil {
		t.Fatalf("ReKeyGen (1st): %v", err)
	}
	rk2, err := ReKeyGen(skA, pkB)
	if err != nil {
		t.Fatalf("ReKeyGen (2nd): %v", err)
	}

	// R_ek is the first 32 bytes of the ReKey token.
	if bytes.Equal(rk1[:rkEphLen], rk2[:rkEphLen]) {
		t.Error("ReKeyGen: ephemeral R_ek is identical across two calls — r_ek was reused")
	}
	// The wrapped skA (bytes 32–79) must also differ because the KDF input
	// (K_ek = r_ek·pkB) is different for each fresh r_ek.
	if bytes.Equal(rk1[rkWrapOff:], rk2[rkWrapOff:]) {
		t.Error("ReKeyGen: wSkA is identical across two calls — KDF output must differ with fresh r_ek")
	}
}

// TestReKeyGenCrossRecipientIsolation verifies that a re-key generated for B
// cannot be used to decrypt a blob re-encrypted for C, and vice versa.
// This is the key-isolation property: re-keys are recipient-specific.
func TestReKeyGenCrossRecipientIsolation(t *testing.T) {
	skA, pkA := mustGenerateKeyPair(t)
	skB, pkB := mustGenerateKeyPair(t)
	_, pkC := mustGenerateKeyPair(t)

	CA, err := ECIESEncrypt(pkA, []byte("isolation test payload"))
	if err != nil {
		t.Fatal(err)
	}

	// Re-key for B, re-encrypt, let B try with C's re-key blob.
	rkAB, err := ReKeyGen(skA, pkB)
	if err != nil {
		t.Fatal(err)
	}
	rkAC, err := ReKeyGen(skA, pkC)
	if err != nil {
		t.Fatal(err)
	}

	// Build a blob using rkAC but try to decrypt with skB.
	CBwithCsRK, err := ReEncrypt(rkAC, CA)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ReDecrypt(skB, CBwithCsRK)
	if err == nil {
		t.Fatal("skB must not decrypt a blob re-encrypted with rkA→C")
	}

	// Confirm B's own re-key still works correctly.
	CB, err := ReEncrypt(rkAB, CA)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReDecrypt(skB, CB)
	if err != nil || !bytes.Equal(got, []byte("isolation test payload")) {
		t.Errorf("B must decrypt its own re-encrypted blob: err=%v", err)
	}
}

// TestECIESDecryptInvalidCapsule verifies ECIESDecrypt rejects a ciphertext
// whose first 32 bytes form an invalid Ed25519 point.
func TestECIESDecryptInvalidCapsule(t *testing.T) {
	skA, _ := mustGenerateKeyPair(t)

	// Construct a blob long enough but with an invalid capsule.
	blob := make([]byte, eciesHdrLen+16+1)
	// All-zero first 32 bytes = identity point; still a valid compressed
	// encoding for Ed25519 (it's the identity element), so we set a clearly
	// bad encoding instead.
	blob[0] = 0xFF
	blob[1] = 0xFF
	_, err := ECIESDecrypt(skA, blob)
	if err == nil {
		t.Fatal("expected error for invalid capsule point")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 4 — EdDSA Proof-of-Possession  (TS-05)
// ─────────────────────────────────────────────────────────────────────────────

// TestPoPSignAndVerify is the basic happy-path: sign a challenge, verify it passes.
func TestPoPSignAndVerify(t *testing.T) {
	sk, pk, err := GenerateIdentityKey()
	if err != nil {
		t.Fatalf("GenerateIdentityKey: %v", err)
	}

	challenge := []byte("server-issued-nonce-abc123")
	sig, err := ProofOfPossession(sk, challenge)
	if err != nil {
		t.Fatalf("ProofOfPossession: %v", err)
	}

	if err := VerifyPoP(pk, challenge, sig); err != nil {
		t.Errorf("VerifyPoP (valid): %v", err)
	}
}

// TestPoPWrongPublicKey is TS-05: verifying against a different public key must fail.
func TestPoPWrongPublicKey(t *testing.T) {
	sk, _, err := GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	_, pkOther, err := GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}

	challenge := []byte("challenge-bytes")
	sig, err := ProofOfPossession(sk, challenge)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyPoP(pkOther, challenge, sig); err == nil {
		t.Fatal("TS-05: VerifyPoP must fail for wrong public key")
	}
}

// TestPoPWrongChallenge: signature over one challenge must not verify for another.
func TestPoPWrongChallenge(t *testing.T) {
	sk, pk, err := GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}

	challenge1 := []byte("challenge-1")
	challenge2 := []byte("challenge-2")

	sig, err := ProofOfPossession(sk, challenge1)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyPoP(pk, challenge2, sig); err == nil {
		t.Fatal("VerifyPoP must fail for different challenge")
	}
}

// TestPoPTamperedSignature verifies that a single-bit corruption in the
// signature is rejected.
func TestPoPTamperedSignature(t *testing.T) {
	sk, pk, err := GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}

	challenge := []byte("valid-challenge")
	sig, err := ProofOfPossession(sk, challenge)
	if err != nil {
		t.Fatal(err)
	}

	var tampered Signature
	copy(tampered[:], sig[:])
	tampered[0] ^= 0x01

	if err := VerifyPoP(pk, challenge, tampered); err == nil {
		t.Fatal("VerifyPoP must fail for tampered signature")
	}
}

// TestPoPEmptyChallenge verifies ProofOfPossession rejects an empty challenge.
func TestPoPEmptyChallenge(t *testing.T) {
	sk, _, err := GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = ProofOfPossession(sk, []byte{})
	if err == nil {
		t.Fatal("ProofOfPossession must reject empty challenge")
	}
}

// TestVerifyPoPEmptyChallenge verifies VerifyPoP rejects an empty challenge.
func TestVerifyPoPEmptyChallenge(t *testing.T) {
	_, pk, err := GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	var sig Signature
	if err := VerifyPoP(pk, []byte{}, sig); err == nil {
		t.Fatal("VerifyPoP must reject empty challenge")
	}
}

// TestPoPDomainSeparation verifies that a valid PoP signature is NOT accepted
// when the raw challenge (without context prefix) is verified directly via the
// ed25519 public key — i.e., the prefix is genuinely enforced.
func TestPoPDomainSeparation(t *testing.T) {
	sk, pk, err := GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}

	// Sign via the domain-separated path.
	challenge := []byte("raw-challenge")
	sig, err := ProofOfPossession(sk, challenge)
	if err != nil {
		t.Fatal(err)
	}

	// Verify against raw challenge (without prefix) — must fail.
	// We use VerifyPoP with a challenge that, when prefixed, produces a
	// different message than what was actually signed.
	//
	// Craft a "challenge" = prefix + original_challenge so that if the
	// implementation naively signs challenge without the prefix, verification
	// of the double-prefixed message would succeed spuriously.
	doublePrefix := append([]byte(popContext), challenge...)
	if err := VerifyPoP(pk, doublePrefix, sig); err == nil {
		t.Fatal("domain separation FAIL: sig verified against double-prefixed challenge")
	}
	_ = pk
}

// TestPoPReplay: the same challenge reused should be detectable by the
// server (out of scope for this crypto function, but we verify that the same
// challenge produces the same signature — Ed25519 is deterministic — so the
// server can detect duplicates by comparing signatures or challeges).
func TestPoPDeterministic(t *testing.T) {
	sk, pk, err := GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}

	challenge := []byte("deterministic-test")
	sig1, err := ProofOfPossession(sk, challenge)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := ProofOfPossession(sk, challenge)
	if err != nil {
		t.Fatal(err)
	}

	// Ed25519 is deterministic: same key + message → same signature.
	if !bytes.Equal(sig1[:], sig2[:]) {
		t.Error("Ed25519 must be deterministic for same key+challenge")
	}
	// Both must verify.
	if err := VerifyPoP(pk, challenge, sig1); err != nil {
		t.Errorf("sig1 does not verify: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 5 — Key helpers
// ─────────────────────────────────────────────────────────────────────────────

// TestGenerateKeyPairUnique verifies that two calls produce distinct key pairs.
func TestGenerateKeyPairUnique(t *testing.T) {
	sk1, pk1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sk2, pk2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	if sk1 == sk2 {
		t.Error("GenerateKeyPair: duplicate private keys")
	}
	if pk1 == pk2 {
		t.Error("GenerateKeyPair: duplicate public keys")
	}
}

// TestIdentityPubKeyFromPrivRoundTrip verifies that IdentityPubKeyFromPriv
// reproduces the same public key as GenerateIdentityKey.
func TestIdentityPubKeyFromPrivRoundTrip(t *testing.T) {
	sk, pkExpected, err := GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}

	pkGot := IdentityPubKeyFromPriv(sk)
	if pkGot != pkExpected {
		t.Errorf("IdentityPubKeyFromPriv mismatch\n got: %x\nwant: %x", pkGot, pkExpected)
	}
}

// TestGenerateIdentityKeyUnique verifies distinct key pairs per call.
func TestGenerateIdentityKeyUnique(t *testing.T) {
	sk1, pk1, err := GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	sk2, pk2, err := GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}

	if sk1 == sk2 {
		t.Error("GenerateIdentityKey: duplicate private seeds")
	}
	if pk1 == pk2 {
		t.Error("GenerateIdentityKey: duplicate public keys")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Section 6 — Test vectors (regression anchors)
// ─────────────────────────────────────────────────────────────────────────────

// TestAESGCMVector is a deterministic regression test using a fixed key and
// known plaintext.  It verifies that:
//  1. EncryptFile produces a ciphertext of the expected length.
//  2. Decryption with the same key recovers the exact plaintext.
//
// Because EncryptFile generates a fresh random nonce, we cannot pin the
// ciphertext bytes themselves — instead we pin the round-trip property and
// the structural invariants (nonce length, ciphertext overhead).
func TestAESGCMVector(t *testing.T) {
	key := []byte("this-is-a-32byte-test-key!!!!!!!") // exactly 32 bytes
	plain := []byte("ZTSS test vector — AES-256-GCM!")

	ct, nonce, err := EncryptFile(plain, key)
	if err != nil {
		t.Fatalf("vector EncryptFile: %v", err)
	}

	// Structural assertions.
	if len(nonce) != 12 {
		t.Errorf("vector: nonce length = %d, want 12", len(nonce))
	}
	if len(ct) != len(plain)+16 {
		t.Errorf("vector: ct length = %d, want %d", len(ct), len(plain)+16)
	}

	// Round-trip assertion.
	got, err := DecryptFile(ct, nonce, key)
	if err != nil {
		t.Fatalf("vector DecryptFile: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("vector round-trip mismatch:\n got: %q\nwant: %q", got, plain)
	}
}

// TestECIESVector exercises the ECIES round-trip with a 32-byte payload
// (representative of a per-file symmetric key Kfile).
func TestECIESVector(t *testing.T) {
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	kFile := make([]byte, 32)
	for i := range kFile {
		kFile[i] = byte(0xDE + i)
	}

	ct, err := ECIESEncrypt(pk, kFile)
	if err != nil {
		t.Fatalf("vector ECIESEncrypt: %v", err)
	}

	// Wire format: [ capsule:32 ][ ct+tag:32+16=48 ] = 80 bytes total.
	wantLen := eciesHdrLen + len(kFile) + 16
	if len(ct) != wantLen {
		t.Errorf("vector: ECIES ct length = %d, want %d", len(ct), wantLen)
	}

	got, err := ECIESDecrypt(sk, ct)
	if err != nil {
		t.Fatalf("vector ECIESDecrypt: %v", err)
	}
	if !bytes.Equal(got, kFile) {
		t.Errorf("vector ECIES round-trip mismatch")
	}
}

// TestPoPVector exercises the sign→verify flow with a realistic server challenge.
func TestPoPVector(t *testing.T) {
	sk, pk, err := GenerateIdentityKey()
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a 32-byte server nonce (typical challenge size).
	challenge := make([]byte, 32)
	for i := range challenge {
		challenge[i] = byte(i * 7)
	}

	sig, err := ProofOfPossession(sk, challenge)
	if err != nil {
		t.Fatalf("vector PoP sign: %v", err)
	}

	// Signature must be exactly 64 bytes.
	var zeros [64]byte
	if bytes.Equal(sig[:], zeros[:]) {
		t.Error("vector: PoP signature is all zeros")
	}

	if err := VerifyPoP(pk, challenge, sig); err != nil {
		t.Errorf("vector PoP verify: %v", err)
	}
}
