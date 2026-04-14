// api_test.go — exhaustive tests for the ztss-api authentication and middleware layer.
//
// CDC test IDs covered:
//   TF-06  expired JWT → HTTP 401
//   TS-03  replayed JWT → HTTP 401
//   TS-05  missing PoP  → HTTP 403
//
// Structure:
//   Section 1  — AuthService unit tests (register, challenge, token issuance)
//   Section 2  — JWT middleware (TF-06, TS-03, malformed, wrong alg)
//   Section 3  — PoP middleware (TS-05, invalid sig, missing headers)
//   Section 4  — Full request pipeline (valid JWT + PoP → 200)
//   Section 5  — Upload endpoint (TS-02 CID mismatch, valid upload)
//   Section 6  — Download endpoint (valid, not-found)
//   Section 7  — Share endpoint (valid, wrong re-key length)
//   Section 8  — Audit endpoint (entries present, signatures non-empty)
//   Section 9  — Middleware chain ordering
package api

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	ztsscrypto "ztss/ztss-crypto"
)

// ── Test fixtures ─────────────────────────────────────────────────────────────

// testEnv bundles everything needed to run a test against the full API stack.
type testEnv struct {
	auth     *AuthService
	auditLog *AuditLog
	store    *memAPIStore
	server   *Server
	tsrv     *httptest.Server // httptest wrapper

	// Registered identity
	identityID string
	sk         ztsscrypto.IdentityPrivKey
	pk         ztsscrypto.IdentityPubKey
}

// memAPIStore is a minimal in-process FileStore for tests (no import cycle).
type memAPIStore struct {
	mu   sync.RWMutex
	data map[[32]byte][]byte
}

func newMemAPIStore() *memAPIStore { return &memAPIStore{data: make(map[[32]byte][]byte)} }
func (m *memAPIStore) Put(cid [32]byte, data []byte) error {
	cp := make([]byte, len(data))
	copy(cp, data)
	m.mu.Lock()
	m.data[cid] = cp
	m.mu.Unlock()
	return nil
}
func (m *memAPIStore) Get(cid [32]byte) ([]byte, error) {
	m.mu.RLock()
	v, ok := m.data[cid]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("ztss/storage: CID not found: %x", cid)
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}
func (m *memAPIStore) Has(cid [32]byte) bool {
	m.mu.RLock()
	_, ok := m.data[cid]
	m.mu.RUnlock()
	return ok
}

// newTestEnv creates a fully wired test environment and registers one identity.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	auth, err := NewAuthService()
	if err != nil {
		t.Fatalf("NewAuthService: %v", err)
	}
	auditLog, err := NewAuditLog()
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}
	store := newMemAPIStore()
	srv := NewServer(auth, auditLog, store)
	tsrv := httptest.NewServer(srv.Handler())
	t.Cleanup(tsrv.Close)

	// Generate and register an identity.
	sk, pk, err := ztsscrypto.GenerateIdentityKey()
	if err != nil {
		t.Fatalf("GenerateIdentityKey: %v", err)
	}
	pkB64 := base64.RawURLEncoding.EncodeToString(pk[:])
	body := fmt.Sprintf(`{"public_key":%q}`, pkB64)

	resp := doRequest(t, tsrv, http.MethodPost, "/auth/register", body, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: got %d, want 201", resp.StatusCode)
	}
	var regResp RegisterResponse
	mustDecode(t, resp.Body, &regResp)

	return &testEnv{
		auth:       auth,
		auditLog:   auditLog,
		store:      store,
		server:     srv,
		tsrv:       tsrv,
		identityID: regResp.IdentityID,
		sk:         sk,
		pk:         pk,
	}
}

// validToken obtains a fresh, valid JWT from POST /auth/token.
func (e *testEnv) validToken(t *testing.T) string {
	t.Helper()

	// GET /auth/challenge.
	resp := doRequest(t, e.tsrv, http.MethodGet, "/auth/challenge", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge: got %d", resp.StatusCode)
	}
	var cr ChallengeResponse
	mustDecode(t, resp.Body, &cr)

	challengeBytes, err := base64.RawURLEncoding.DecodeString(cr.Challenge)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}

	sig, err := ztsscrypto.ProofOfPossession(e.sk, challengeBytes)
	if err != nil {
		t.Fatalf("ProofOfPossession: %v", err)
	}

	body := fmt.Sprintf(`{"identity_id":%q,"challenge_id":%q,"pop_signature":%q}`,
		e.identityID, cr.ChallengeID,
		base64.RawURLEncoding.EncodeToString(sig[:]),
	)
	resp = doRequest(t, e.tsrv, http.MethodPost, "/auth/token", body, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("token: got %d: %s", resp.StatusCode, b)
	}
	var tr TokenResponse
	mustDecode(t, resp.Body, &tr)
	return tr.Token
}

// popHeaders builds X-ZTSS-Challenge + X-ZTSS-PoP headers for a protected request.
func (e *testEnv) popHeaders(t *testing.T) map[string]string {
	t.Helper()
	challenge := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, challenge); err != nil {
		t.Fatal(err)
	}
	sig, err := ztsscrypto.ProofOfPossession(e.sk, challenge)
	if err != nil {
		t.Fatalf("ProofOfPossession: %v", err)
	}
	return map[string]string{
		"X-ZTSS-Challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"X-ZTSS-PoP":       base64.RawURLEncoding.EncodeToString(sig[:]),
	}
}

// authHeaders returns Authorization + PoP headers for a protected request.
func (e *testEnv) authHeaders(t *testing.T) map[string]string {
	t.Helper()
	token := e.validToken(t)
	hdrs := e.popHeaders(t)
	hdrs["Authorization"] = "Bearer " + token
	return hdrs
}

// doRequest performs an HTTP request against tsrv.
func doRequest(t *testing.T, tsrv *httptest.Server, method, path, body string, headers map[string]string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, tsrv.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP %s %s: %v", method, path, err)
	}
	return resp
}

func mustDecode(t *testing.T, r io.ReadCloser, v any) {
	t.Helper()
	defer r.Close()
	if err := json.NewDecoder(r).Decode(v); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

// ── Section 1 — AuthService unit tests ───────────────────────────────────────

// TestRegisterValidKey verifies POST /auth/register with a valid Ed25519 key.
func TestRegisterValidKey(t *testing.T) {
	e := newTestEnv(t)
	if e.identityID == "" {
		t.Fatal("register: identity_id is empty")
	}
	// Identity must be stored.
	if _, ok := e.auth.LookupIdentity(e.identityID); !ok {
		t.Fatal("registered identity not found in AuthService")
	}
}

// TestRegisterMissingKey verifies POST /auth/register with no public_key → 400.
func TestRegisterMissingKey(t *testing.T) {
	e := newTestEnv(t)
	resp := doRequest(t, e.tsrv, http.MethodPost, "/auth/register", `{}`, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

// TestRegisterShortKey verifies that a key shorter than 32 bytes → 400.
func TestRegisterShortKey(t *testing.T) {
	e := newTestEnv(t)
	shortKey := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	body := fmt.Sprintf(`{"public_key":%q}`, shortKey)
	resp := doRequest(t, e.tsrv, http.MethodPost, "/auth/register", body, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for short key, got %d", resp.StatusCode)
	}
}

// TestChallengeIsUnique verifies that two GET /auth/challenge calls return
// different challenges.
func TestChallengeIsUnique(t *testing.T) {
	e := newTestEnv(t)

	r1 := doRequest(t, e.tsrv, http.MethodGet, "/auth/challenge", "", nil)
	r2 := doRequest(t, e.tsrv, http.MethodGet, "/auth/challenge", "", nil)

	var c1, c2 ChallengeResponse
	mustDecode(t, r1.Body, &c1)
	mustDecode(t, r2.Body, &c2)

	if c1.Challenge == c2.Challenge {
		t.Error("two consecutive challenges must be distinct")
	}
	if c1.ChallengeID == c2.ChallengeID {
		t.Error("two consecutive challenge IDs must be distinct")
	}
}

// TestChallengeConsumedOnToken verifies that a challenge cannot be used twice:
// the first /auth/token call succeeds; the second must be rejected (→ 403).
func TestChallengeConsumedOnToken(t *testing.T) {
	e := newTestEnv(t)

	resp := doRequest(t, e.tsrv, http.MethodGet, "/auth/challenge", "", nil)
	var cr ChallengeResponse
	mustDecode(t, resp.Body, &cr)
	challengeBytes, _ := base64.RawURLEncoding.DecodeString(cr.Challenge)

	sig, _ := ztsscrypto.ProofOfPossession(e.sk, challengeBytes)
	body := fmt.Sprintf(`{"identity_id":%q,"challenge_id":%q,"pop_signature":%q}`,
		e.identityID, cr.ChallengeID,
		base64.RawURLEncoding.EncodeToString(sig[:]),
	)

	// First use → 200.
	r1 := doRequest(t, e.tsrv, http.MethodPost, "/auth/token", body, nil)
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("first token call: got %d, want 200", r1.StatusCode)
	}
	r1.Body.Close()

	// Second use with SAME challenge → 403 (challenge already consumed).
	r2 := doRequest(t, e.tsrv, http.MethodPost, "/auth/token", body, nil)
	if r2.StatusCode != http.StatusForbidden {
		t.Errorf("TS-05: replayed challenge: got %d, want 403", r2.StatusCode)
	}
	r2.Body.Close()
}

// TestTokenUnknownIdentity verifies POST /auth/token with an unknown identity_id → 401.
func TestTokenUnknownIdentity(t *testing.T) {
	e := newTestEnv(t)

	resp := doRequest(t, e.tsrv, http.MethodGet, "/auth/challenge", "", nil)
	var cr ChallengeResponse
	mustDecode(t, resp.Body, &cr)

	body := fmt.Sprintf(`{"identity_id":"nonexistent","challenge_id":%q,"pop_signature":"AAAA"}`, cr.ChallengeID)
	r := doRequest(t, e.tsrv, http.MethodPost, "/auth/token", body, nil)
	if r.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for unknown identity, got %d", r.StatusCode)
	}
	r.Body.Close()
}

// TestTokenInvalidPoP verifies POST /auth/token with a bogus sig → 403 (TS-05).
func TestTokenInvalidPoP(t *testing.T) {
	e := newTestEnv(t)

	resp := doRequest(t, e.tsrv, http.MethodGet, "/auth/challenge", "", nil)
	var cr ChallengeResponse
	mustDecode(t, resp.Body, &cr)

	badSig := base64.RawURLEncoding.EncodeToString(make([]byte, 64)) // all-zero sig
	body := fmt.Sprintf(`{"identity_id":%q,"challenge_id":%q,"pop_signature":%q}`,
		e.identityID, cr.ChallengeID, badSig)
	r := doRequest(t, e.tsrv, http.MethodPost, "/auth/token", body, nil)
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("TS-05: invalid PoP on /auth/token: got %d, want 403", r.StatusCode)
	}
	r.Body.Close()
}

// TestIssueTokenReturns300Expiry verifies that the issued JWT expires_in == 300.
func TestIssueTokenReturns300Expiry(t *testing.T) {
	e := newTestEnv(t)
	_ = e.validToken(t)

	// Also verify the JWT header+payload directly.
	token := e.validToken(t)
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		t.Fatal("token is not a 3-part JWT")
	}
	payJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var payload struct {
		Iat int64 `json:"iat"`
		Exp int64 `json:"exp"`
	}
	if err = json.Unmarshal(payJSON, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	ttl := payload.Exp - payload.Iat
	if ttl != int64(JWTTTL.Seconds()) {
		t.Errorf("JWT TTL = %d s, want %d s", ttl, int64(JWTTTL.Seconds()))
	}
	if ttl > 300 {
		t.Errorf("JWT TTL %d s exceeds mandatory 300 s", ttl)
	}
}

// ── Section 2 — JWT middleware tests (TF-06, TS-03) ──────────────────────────

// TestExpiredJWT_Returns401 is TF-06: an expired RS256 JWT must return HTTP 401.
func TestExpiredJWT_Returns401(t *testing.T) {
	e := newTestEnv(t)

	// Craft a JWT with exp already in the past using the server's private key.
	expiredToken := craftExpiredJWT(t, e.auth)

	hdrs := map[string]string{"Authorization": "Bearer " + expiredToken}
	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", `{}`, hdrs)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("TF-06: expired JWT: got %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

// craftExpiredJWT creates a signed JWT that expired 10 minutes ago.
// Uses the server's real RSA key so the signature is valid — only exp is stale.
func craftExpiredJWT(t *testing.T, auth *AuthService) string {
	t.Helper()
	// Shift iat/exp 10 minutes into the past so exp < now.
	now := time.Now().Add(-10 * time.Minute).Unix()
	payload := jwtPayload{
		Sub: "test-expired-subject",
		Iat: now,
		Exp: now + int64(JWTTTL.Seconds()),
		Jti: fmt.Sprintf("expired-jti-%d", time.Now().UnixNano()),
	}
	payJSON, _ := json.Marshal(payload)
	payB64 := base64.RawURLEncoding.EncodeToString(payJSON)
	signingInput := jwtHeader + "." + payB64
	digest := sha256.Sum256([]byte(signingInput))
	rawSig, _ := rsa.SignPKCS1v15(rand.Reader, auth.serverKey, crypto.SHA256, digest[:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(rawSig)
}

// TestReplayedJWT_Returns401 is TS-03: reusing an already-seen JWT jti → 401.
func TestReplayedJWT_Returns401(t *testing.T) {
	e := newTestEnv(t)
	token := e.validToken(t)
	popHdrs := e.popHeaders(t)

	hdrs := func() map[string]string {
		h := map[string]string{"Authorization": "Bearer " + token}
		// Each request gets fresh PoP headers.
		ph := e.popHeaders(t)
		h["X-ZTSS-Challenge"] = ph["X-ZTSS-Challenge"]
		h["X-ZTSS-PoP"] = ph["X-ZTSS-PoP"]
		return h
	}

	// First request succeeds (hits /audit which is public — use /upload to go
	// through the JWT middleware; it will 400 on bad body but JWT is 200 path).
	// Use a valid upload to avoid the body rejection short-circuit.
	data := []byte("some-ciphertext-payload")
	cid := sha256.Sum256(data)

	chunk := map[string]interface{}{
		"index": 0,
		"cid":   hex.EncodeToString(cid[:]),
		"data":  base64.StdEncoding.EncodeToString(data),
	}
	uploadBody, _ := json.Marshal(map[string]interface{}{
		"root_cid": hex.EncodeToString(cid[:]),
		"chunks":   []interface{}{chunk},
	})

	h1 := map[string]string{
		"Authorization":    "Bearer " + token,
		"X-ZTSS-Challenge": popHdrs["X-ZTSS-Challenge"],
		"X-ZTSS-PoP":       popHdrs["X-ZTSS-PoP"],
	}
	r1 := doRequest(t, e.tsrv, http.MethodPost, "/upload", string(uploadBody), h1)
	r1.Body.Close()
	// Acceptable outcomes: 201 (success) or anything ≥ 400 but NOT 401
	// (JWT itself should pass on first use).
	if r1.StatusCode == http.StatusUnauthorized {
		t.Fatalf("TS-03: first use of JWT got 401 — should succeed")
	}

	// Second request with SAME token — jti is in the replay cache → 401.
	h2 := hdrs()
	r2 := doRequest(t, e.tsrv, http.MethodPost, "/upload", string(uploadBody), h2)
	if r2.StatusCode != http.StatusUnauthorized {
		t.Errorf("TS-03: replayed JWT: got %d, want 401", r2.StatusCode)
	}
	r2.Body.Close()
}

// TestMissingAuthHeader_Returns401 verifies that a missing Authorization header → 401.
func TestMissingAuthHeader_Returns401(t *testing.T) {
	e := newTestEnv(t)
	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", `{}`, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("missing auth header: got %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestMalformedBearerToken_Returns401 verifies that a garbled token → 401.
func TestMalformedBearerToken_Returns401(t *testing.T) {
	e := newTestEnv(t)
	hdrs := map[string]string{"Authorization": "Bearer not.a.jwt"}
	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", `{}`, hdrs)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("malformed JWT: got %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestWrongAlgorithmToken_Returns401 verifies that alg:HS256 is rejected → 401.
func TestWrongAlgorithmToken_Returns401(t *testing.T) {
	e := newTestEnv(t)
	// Build a HS256 claim set — signature won't matter, alg check comes first.
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x","iat":1,"exp":9999999999,"jti":"x"}`))
	fakeToken := hdr + "." + pay + ".fakesig"

	hdrs := map[string]string{"Authorization": "Bearer " + fakeToken}
	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", `{}`, hdrs)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("HS256 token: got %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestTTLExceeds300s_Returns401 crafts a JWT with exp-iat > 300 → 401.
func TestTTLExceeds300s_Returns401(t *testing.T) {
	e := newTestEnv(t)
	token := craftLongLivedJWT(t, e.auth, 600) // 600s TTL
	hdrs := map[string]string{"Authorization": "Bearer " + token}
	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", `{}`, hdrs)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("600s TTL JWT: got %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func craftLongLivedJWT(t *testing.T, auth *AuthService, ttlSeconds int64) string {
	t.Helper()
	now := time.Now().Unix()
	payload := jwtPayload{
		Sub: "test-long-lived",
		Iat: now,
		Exp: now + ttlSeconds,
		Jti: fmt.Sprintf("long-jti-%d", time.Now().UnixNano()),
	}
	payJSON, _ := json.Marshal(payload)
	payB64 := base64.RawURLEncoding.EncodeToString(payJSON)
	signingInput := jwtHeader + "." + payB64
	digest := sha256.Sum256([]byte(signingInput))
	rawSig, _ := rsa.SignPKCS1v15(rand.Reader, auth.serverKey, crypto.SHA256, digest[:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(rawSig)
}

// ── Section 3 — PoP middleware tests (TS-05) ─────────────────────────────────

// TestMissingPoPHeader_Returns403 is TS-05: a valid JWT but no X-ZTSS-PoP → 403.
func TestMissingPoPHeader_Returns403(t *testing.T) {
	e := newTestEnv(t)
	token := e.validToken(t)

	// No PoP headers at all.
	hdrs := map[string]string{"Authorization": "Bearer " + token}
	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", `{}`, hdrs)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("TS-05: missing PoP: got %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestMissingChallengeHeader_Returns403 is TS-05: valid JWT + PoP sig but no
// X-ZTSS-Challenge → 403.
func TestMissingChallengeHeader_Returns403(t *testing.T) {
	e := newTestEnv(t)
	token := e.validToken(t)
	fakeSig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	hdrs := map[string]string{
		"Authorization": "Bearer " + token,
		// X-ZTSS-Challenge deliberately omitted.
		"X-ZTSS-PoP": fakeSig,
	}
	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", `{}`, hdrs)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("TS-05: missing challenge header: got %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestInvalidPoPSignature_Returns403 verifies that a syntactically present but
// cryptographically invalid PoP → 403 (TS-05).
func TestInvalidPoPSignature_Returns403(t *testing.T) {
	e := newTestEnv(t)
	token := e.validToken(t)

	challenge := make([]byte, 32)
	rand.Read(challenge)
	badSig := make([]byte, 64) // all-zero; invalid for any key/challenge

	hdrs := map[string]string{
		"Authorization":    "Bearer " + token,
		"X-ZTSS-Challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"X-ZTSS-PoP":       base64.RawURLEncoding.EncodeToString(badSig),
	}
	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", `{}`, hdrs)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("TS-05: invalid PoP sig: got %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestPoPSignedByWrongKey_Returns403 verifies that a PoP signed by a different
// key (not the registered one) is rejected → 403.
func TestPoPSignedByWrongKey_Returns403(t *testing.T) {
	e := newTestEnv(t)
	token := e.validToken(t)

	// Generate a different key pair — NOT registered.
	wrongSK, _, _ := ztsscrypto.GenerateIdentityKey()
	challenge := make([]byte, 32)
	rand.Read(challenge)
	sig, _ := ztsscrypto.ProofOfPossession(wrongSK, challenge) // signed by wrong key

	hdrs := map[string]string{
		"Authorization":    "Bearer " + token,
		"X-ZTSS-Challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"X-ZTSS-PoP":       base64.RawURLEncoding.EncodeToString(sig[:]),
	}
	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", `{}`, hdrs)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("TS-05: PoP from wrong key: got %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestPoPSigTooShort_Returns403 verifies that a truncated base64 PoP → 403.
func TestPoPSigTooShort_Returns403(t *testing.T) {
	e := newTestEnv(t)
	token := e.validToken(t)
	challenge := make([]byte, 32)
	rand.Read(challenge)

	hdrs := map[string]string{
		"Authorization":    "Bearer " + token,
		"X-ZTSS-Challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"X-ZTSS-PoP":       base64.RawURLEncoding.EncodeToString(make([]byte, 32)), // 32, not 64
	}
	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", `{}`, hdrs)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("short PoP sig: got %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

// ── Section 4 — Full authenticated pipeline ───────────────────────────────────

// TestValidRequestReachesHandler verifies that a request with a valid JWT + PoP
// reaches the handler (not blocked by middleware).  We probe /upload with a
// valid chunk to get 201.
func TestValidRequestReachesHandler(t *testing.T) {
	e := newTestEnv(t)
	hdrs := e.authHeaders(t)

	data := []byte("valid ciphertext payload")
	cid := sha256.Sum256(data)
	body := buildUploadBody(t, cid, data)

	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", body, hdrs)
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Errorf("valid request: got %d, want 201: %s", resp.StatusCode, b)
	}
	resp.Body.Close()
}

// ── Section 5 — Upload endpoint ───────────────────────────────────────────────

// TestUploadValidChunk verifies the full upload flow and response shape.
func TestUploadValidChunk(t *testing.T) {
	e := newTestEnv(t)
	hdrs := e.authHeaders(t)

	data := []byte("my encrypted file content")
	cid := sha256.Sum256(data)
	rootCIDhex := hex.EncodeToString(cid[:])
	body := buildUploadBody(t, cid, data)

	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", body, hdrs)
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("upload: got %d: %s", resp.StatusCode, b)
	}

	var ur UploadResponse
	mustDecode(t, resp.Body, &ur)
	if ur.RootCID != rootCIDhex {
		t.Errorf("root_cid: got %q, want %q", ur.RootCID, rootCIDhex)
	}
	if ur.ChunksCount != 1 {
		t.Errorf("chunks_count: got %d, want 1", ur.ChunksCount)
	}
}

// TestUploadCIDMismatch_Returns400 is TS-02: a chunk with wrong CID → 400.
func TestUploadCIDMismatch_Returns400(t *testing.T) {
	e := newTestEnv(t)
	hdrs := e.authHeaders(t)

	data := []byte("authentic data")
	realCID := sha256.Sum256(data)

	var badCID [32]byte
	copy(badCID[:], realCID[:])
	badCID[0] ^= 0xFF

	body := buildUploadBodyRaw(t, hex.EncodeToString(badCID[:]), badCID, data)
	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", body, hdrs)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("TS-02: CID mismatch: got %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestUploadEmptyChunks_Returns400 verifies that an empty chunks array → 400.
func TestUploadEmptyChunks_Returns400(t *testing.T) {
	e := newTestEnv(t)
	hdrs := e.authHeaders(t)

	body := `{"root_cid":"aabbcc","chunks":[]}`
	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", body, hdrs)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("empty chunks: got %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestUploadMultipleChunks verifies that multi-chunk uploads are catalogued correctly.
func TestUploadMultipleChunks(t *testing.T) {
	e := newTestEnv(t)
	hdrs := e.authHeaders(t)

	chunks := make([]ChunkUpload, 3)
	cidBytes := make([][32]byte, 3)
	for i := range chunks {
		d := []byte(fmt.Sprintf("chunk-%d-data", i))
		cid := sha256.Sum256(d)
		cidBytes[i] = cid
		chunks[i] = ChunkUpload{
			Index: uint64(i),
			CID:   hex.EncodeToString(cid[:]),
			Data:  base64.StdEncoding.EncodeToString(d),
		}
	}
	// Compose a fake root CID (in prod the client computes the Merkle root).
	rootCID := hex.EncodeToString(cidBytes[0][:])

	req := UploadRequest{RootCID: rootCID, Chunks: chunks}
	bodyBytes, _ := json.Marshal(req)
	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", string(bodyBytes), hdrs)
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("multi-chunk upload: got %d: %s", resp.StatusCode, b)
	}
	var ur UploadResponse
	mustDecode(t, resp.Body, &ur)
	if ur.ChunksCount != 3 {
		t.Errorf("chunks_count: got %d, want 3", ur.ChunksCount)
	}
}

// ── Section 6 — Download endpoint ────────────────────────────────────────────

// TestDownloadAfterUpload verifies GET /download/:cid returns the uploaded chunk.
func TestDownloadAfterUpload(t *testing.T) {
	e := newTestEnv(t)

	// Upload a chunk.
	data := []byte("ciphertext-for-download-test")
	cid := sha256.Sum256(data)
	rootCIDhex := hex.EncodeToString(cid[:])
	body := buildUploadBody(t, cid, data)

	upHdrs := e.authHeaders(t)
	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", body, upHdrs)
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("upload before download: %d: %s", resp.StatusCode, b)
	}
	resp.Body.Close()

	// Download with a fresh JWT + PoP.
	dlHdrs := e.authHeaders(t)
	dlResp := doRequest(t, e.tsrv, http.MethodGet, "/download/"+rootCIDhex, "", dlHdrs)
	if dlResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(dlResp.Body)
		t.Fatalf("download: got %d: %s", dlResp.StatusCode, b)
	}

	var chunks []struct {
		Index int    `json:"index"`
		CID   string `json:"cid"`
		Data  string `json:"data"`
	}
	mustDecode(t, dlResp.Body, &chunks)

	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}
	gotData, err := base64.StdEncoding.DecodeString(chunks[0].Data)
	if err != nil {
		t.Fatalf("decode chunk data: %v", err)
	}
	if !bytes.Equal(gotData, data) {
		t.Error("download: returned data does not match uploaded data")
	}
}

// TestDownloadNotFound_Returns404 verifies that GET /download/<unknown> → 404.
func TestDownloadNotFound_Returns404(t *testing.T) {
	e := newTestEnv(t)
	hdrs := e.authHeaders(t)

	fakeCID := hex.EncodeToString(make([]byte, 32))
	resp := doRequest(t, e.tsrv, http.MethodGet, "/download/"+fakeCID, "", hdrs)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("download not found: got %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

// ── Section 7 — Share endpoint ────────────────────────────────────────────────

// TestShareValidReKey verifies POST /share with a valid 80-byte re-key.
func TestShareValidReKey(t *testing.T) {
	e := newTestEnv(t)

	// First upload a file.
	data := []byte("data-to-share")
	cid := sha256.Sum256(data)
	rootCIDhex := hex.EncodeToString(cid[:])

	upHdrs := e.authHeaders(t)
	uresp := doRequest(t, e.tsrv, http.MethodPost, "/upload", buildUploadBody(t, cid, data), upHdrs)
	if uresp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(uresp.Body)
		t.Fatalf("upload for share: %d: %s", uresp.StatusCode, b)
	}
	uresp.Body.Close()

	// POST /share with an 80-byte re-key.
	reKey := base64.StdEncoding.EncodeToString(make([]byte, 80))
	shareBody := fmt.Sprintf(`{"root_cid":%q,"delegatee_id":"delegatee-123","re_key":%q}`,
		rootCIDhex, reKey)

	shrHdrs := e.authHeaders(t)
	sresp := doRequest(t, e.tsrv, http.MethodPost, "/share", shareBody, shrHdrs)
	if sresp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(sresp.Body)
		t.Fatalf("share: got %d: %s", sresp.StatusCode, b)
	}

	var sr ShareResponse
	mustDecode(t, sresp.Body, &sr)
	if sr.DelegatedCID != rootCIDhex {
		t.Errorf("delegated_cid: got %q, want %q", sr.DelegatedCID, rootCIDhex)
	}
}

// TestShareWrongReKeyLength_Returns400 verifies that a re-key ≠ 80 bytes → 400.
func TestShareWrongReKeyLength_Returns400(t *testing.T) {
	e := newTestEnv(t)

	// Upload first.
	data := []byte("file-for-bad-share")
	cid := sha256.Sum256(data)
	rootCIDhex := hex.EncodeToString(cid[:])
	upHdrs := e.authHeaders(t)
	r := doRequest(t, e.tsrv, http.MethodPost, "/upload", buildUploadBody(t, cid, data), upHdrs)
	r.Body.Close()

	// Share with a 32-byte re-key (wrong length).
	reKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	shareBody := fmt.Sprintf(`{"root_cid":%q,"delegatee_id":"x","re_key":%q}`, rootCIDhex, reKey)

	shrHdrs := e.authHeaders(t)
	resp := doRequest(t, e.tsrv, http.MethodPost, "/share", shareBody, shrHdrs)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("wrong re-key length: got %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestShareUnknownFile_Returns404 verifies that sharing a non-uploaded file → 404.
func TestShareUnknownFile_Returns404(t *testing.T) {
	e := newTestEnv(t)
	reKey := base64.StdEncoding.EncodeToString(make([]byte, 80))
	shareBody := fmt.Sprintf(`{"root_cid":"deadbeef00000000000000000000000000000000000000000000000000000000","delegatee_id":"x","re_key":%q}`, reKey)

	hdrs := e.authHeaders(t)
	resp := doRequest(t, e.tsrv, http.MethodPost, "/share", shareBody, hdrs)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("share unknown file: got %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

// ── Section 8 — Audit endpoint ───────────────────────────────────────────────

// TestAuditLogRecordsHit verifies that GET /audit returns signed entries after
// protected endpoint activity.
func TestAuditLogRecordsHit(t *testing.T) {
	e := newTestEnv(t)

	// Make a protected request to generate an audit entry.
	data := []byte("audit-test-chunk")
	cid := sha256.Sum256(data)
	hdrs := e.authHeaders(t)
	doRequest(t, e.tsrv, http.MethodPost, "/upload", buildUploadBody(t, cid, data), hdrs).Body.Close()

	// GET /audit (public).
	resp := doRequest(t, e.tsrv, http.MethodGet, "/audit", "", nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("audit: got %d: %s", resp.StatusCode, b)
	}

	var entries []AuditEntry
	mustDecode(t, resp.Body, &entries)
	if len(entries) == 0 {
		t.Fatal("audit log is empty after a successful request")
	}

	// Every entry must have a non-empty signature.
	for i, entry := range entries {
		if entry.Sig == "" {
			t.Errorf("audit entry %d: Sig is empty (ES5 violation)", i)
		}
		if entry.Timestamp == "" {
			t.Errorf("audit entry %d: Timestamp is empty", i)
		}
		if entry.Action == "" {
			t.Errorf("audit entry %d: Action is empty", i)
		}
	}
}

// TestAuditLogsIdentityID verifies that audit entries capture the identity_id
// of the authenticated caller.
func TestAuditLogsIdentityID(t *testing.T) {
	e := newTestEnv(t)

	data := []byte("audit-identity-test")
	cid := sha256.Sum256(data)
	hdrs := e.authHeaders(t)
	doRequest(t, e.tsrv, http.MethodPost, "/upload", buildUploadBody(t, cid, data), hdrs).Body.Close()

	resp := doRequest(t, e.tsrv, http.MethodGet, "/audit", "", nil)
	var entries []AuditEntry
	mustDecode(t, resp.Body, &entries)

	found := false
	for _, entry := range entries {
		if entry.IdentityID == e.identityID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("audit log does not contain an entry for identity %q", e.identityID)
	}
}

// ── Section 9 — Middleware chain ordering ─────────────────────────────────────

// TestJWTCheckedBeforePoP verifies that a missing JWT (→ 401) takes precedence
// over a missing PoP (→ 403): the JWT middleware runs first.
func TestJWTCheckedBeforePoP(t *testing.T) {
	e := newTestEnv(t)

	// No Authorization header, no PoP headers.
	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", `{}`, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("missing JWT + PoP: expected 401 (JWT checked first), got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestValidJWTButMissingPoP verifies the ordering: valid JWT passes → PoP
// middleware enforces 403.
func TestValidJWTButMissingPoP(t *testing.T) {
	e := newTestEnv(t)
	token := e.validToken(t)

	// Valid JWT, no PoP.
	hdrs := map[string]string{"Authorization": "Bearer " + token}
	resp := doRequest(t, e.tsrv, http.MethodPost, "/upload", `{}`, hdrs)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("valid JWT, missing PoP: expected 403, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestAuthEndpointsArePublic verifies that /auth/* routes do NOT require JWT or PoP.
func TestAuthEndpointsArePublic(t *testing.T) {
	e := newTestEnv(t)

	// GET /auth/challenge must succeed with no headers.
	resp := doRequest(t, e.tsrv, http.MethodGet, "/auth/challenge", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/auth/challenge with no headers: got %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// /audit must be accessible with no headers.
	resp = doRequest(t, e.tsrv, http.MethodGet, "/audit", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/audit with no headers: got %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
	_ = e
}

// ── Payload builder helpers ───────────────────────────────────────────────────

// buildUploadBody constructs a valid single-chunk upload JSON body.
func buildUploadBody(t *testing.T, cid [32]byte, data []byte) string {
	t.Helper()
	return buildUploadBodyRaw(t, hex.EncodeToString(cid[:]), cid, data)
}

// buildUploadBodyRaw constructs an upload body with explicit root_cid and chunk CID.
// Allows injecting a wrong CID for negative tests.
func buildUploadBodyRaw(t *testing.T, rootCIDhex string, chunkCID [32]byte, data []byte) string {
	t.Helper()
	req := UploadRequest{
		RootCID: rootCIDhex,
		Chunks: []ChunkUpload{
			{
				Index: 0,
				CID:   hex.EncodeToString(chunkCID[:]),
				Data:  base64.StdEncoding.EncodeToString(data),
			},
		},
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal upload body: %v", err)
	}
	return string(b)
}
