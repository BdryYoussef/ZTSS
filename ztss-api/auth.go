// auth.go — ZTSS auth service: POST /auth/register, POST /auth/token,
// GET /auth/challenge, and the RSA-2048 server signing key.
//
// ── Identity model ────────────────────────────────────────────────────────────
//
//   Client generates:
//     - IdentityPrivKey / IdentityPubKey  (Ed25519, for PoP)
//     - RSA-2048 key pair                 (for JWT issuance & verification)
//
//   POST /auth/register  →  stores (identity_id, EdDSA pub key), returns identity_id
//   GET  /auth/challenge →  issues a fresh 32-byte random challenge (one-time use)
//   POST /auth/token     →  verifies PoP over challenge, issues RS256 JWT (TTL=300s)
//
// ── JWT format ────────────────────────────────────────────────────────────────
//
//   Header:  { "alg": "RS256", "typ": "JWT" }
//   Payload: { "sub": <identity_id>, "iat": <unix>, "exp": <iat+300>, "jti": <uuid> }
//   Signature: RSA-PKCS1v15(SHA-256(base64url(header).base64url(payload)), serverPrivKey)
//
// ── Security constraints ──────────────────────────────────────────────────────
//
//   ES1: every token request is validated against the stored EdDSA PoP.
//   TS-03: jti (JWT ID) is stored in a replay cache; reuse returns 401.
//   TTL is HARD-WIRED to 300 s; the issuer rejects its own tokens after expiry.
//
// Wiki references:
//   - [[api_auth_layer#Auth Service]]
//   - [[auth_requirements#JWT]]
//   - [[auth_requirements#Proof-of-Possession]]
//   - [[security_rules#ES1]]
package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	ztsscrypto "ztss/ztss-crypto"
)

// ── Constants ─────────────────────────────────────────────────────────────────

const (
	// JWTAlg is the mandatory JWT algorithm (wiki/auth_requirements.md §JWT).
	JWTAlg = "RS256"

	// JWTTTL is the hard-wired token lifetime (wiki/auth_requirements.md §JWT: ≤300s).
	JWTTTL = 300 * time.Second

	// ChallengeSize is the length of server-issued challenges in bytes.
	// 32 bytes = 256 bits of entropy (well beyond replay-attack threshold).
	ChallengeSize = 32

	// rsaKeyBits is the server RSA private key size.
	rsaKeyBits = 2048
)

// ── AuthService ───────────────────────────────────────────────────────────────

// AuthService manages identity registration, challenge issuance, and token
// signing.  A single AuthService is shared across all API handlers.
//
// Thread-safe: all maps are protected by sync.RWMutex.
type AuthService struct {
	// serverKey is the RSA-2048 signing key.  Its public half is used by the
	// middleware to verify JWT signatures.
	serverKey    *rsa.PrivateKey
	ServerPubKey *rsa.PublicKey // exported for middleware

	// identities maps identity_id → Ed25519 public key (32 bytes).
	identities   map[string]ztsscrypto.IdentityPubKey
	identMu      sync.RWMutex

	// challenges is a one-time-use store of server-issued challenges.
	// A challenge is deleted the moment it is consumed in /auth/token.
	// challenge_id → challenge bytes.
	challenges   map[string][]byte
	challengeMu  sync.Mutex

	// jtiCache is the JWT-ID replay cache (TS-03).
	// Entries expire after JWTTTL so the cache does not grow unbounded.
	jtiCache     map[string]time.Time
	jtiMu        sync.Mutex
}

// NewAuthService creates an AuthService with a freshly generated RSA-2048 key.
func NewAuthService() (*AuthService, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("ztss/api: NewAuthService: RSA key gen: %w", err)
	}
	return &AuthService{
		serverKey:    priv,
		ServerPubKey: &priv.PublicKey,
		identities:   make(map[string]ztsscrypto.IdentityPubKey),
		challenges:   make(map[string][]byte),
		jtiCache:     make(map[string]time.Time),
	}, nil
}

// ServerPublicKeyPEM returns the server's RSA public key in PEM format.
// Exposed for testing and for the optional GET /auth/pubkey endpoint.
func (a *AuthService) ServerPublicKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(a.ServerPubKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ── POST /auth/register ───────────────────────────────────────────────────────

// RegisterRequest is the JSON body of POST /auth/register.
//
//	{
//	  "public_key": "<base64url-encoded 32-byte Ed25519 public key>"
//	}
type RegisterRequest struct {
	PublicKey string `json:"public_key"` // base64url, 32 bytes
}

// RegisterResponse is the JSON body returned by POST /auth/register.
//
//	{
//	  "identity_id": "<opaque string>",
//	  "public_key":  "<base64url>"
//	}
type RegisterResponse struct {
	IdentityID string `json:"identity_id"`
	PublicKey  string `json:"public_key"`
}

// HandleRegister implements POST /auth/register.
//
// Stores the client's Ed25519 public key under a randomly generated
// identity_id and returns it.  The identity_id is subsequently included in
// JWT claims as the "sub" field.
func (a *AuthService) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.PublicKey == "" {
		jsonError(w, "public_key is required", http.StatusBadRequest)
		return
	}

	// Decode the base64url-encoded public key.
	pkBytes, err := base64.RawURLEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pkBytes) != 32 {
		jsonError(w, "public_key must be base64url-encoded 32-byte Ed25519 key", http.StatusBadRequest)
		return
	}

	var pk ztsscrypto.IdentityPubKey
	copy(pk[:], pkBytes)

	// Generate a unique identity_id (32 random bytes, base64url).
	id, err := randomBase64(32)
	if err != nil {
		jsonError(w, "failed to generate identity_id", http.StatusInternalServerError)
		return
	}

	a.identMu.Lock()
	a.identities[id] = pk
	a.identMu.Unlock()

	writeJSON(w, http.StatusCreated, RegisterResponse{
		IdentityID: id,
		PublicKey:  req.PublicKey,
	})
}

// ── GET /auth/challenge ───────────────────────────────────────────────────────

// ChallengeResponse is the JSON body returned by GET /auth/challenge.
//
//	{
//	  "challenge_id": "<id>",
//	  "challenge":    "<base64url-encoded 32 random bytes>"
//	}
type ChallengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Challenge   string `json:"challenge"`
}

// HandleChallenge implements GET /auth/challenge.
//
// Issues a fresh one-time challenge for the client to sign.  The challenge is
// stored server-side and consumed (deleted) when /auth/token verifies it.
// This prevents replay of the same challenge.
func (a *AuthService) HandleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cid, err := randomBase64(16)
	if err != nil {
		jsonError(w, "challenge generation failed", http.StatusInternalServerError)
		return
	}

	rawChallenge := make([]byte, ChallengeSize)
	if _, err = io.ReadFull(rand.Reader, rawChallenge); err != nil {
		jsonError(w, "challenge generation failed", http.StatusInternalServerError)
		return
	}

	a.challengeMu.Lock()
	a.challenges[cid] = rawChallenge
	a.challengeMu.Unlock()

	writeJSON(w, http.StatusOK, ChallengeResponse{
		ChallengeID: cid,
		Challenge:   base64.RawURLEncoding.EncodeToString(rawChallenge),
	})
}

// ── POST /auth/token ──────────────────────────────────────────────────────────

// TokenRequest is the JSON body of POST /auth/token.
//
//	{
//	  "identity_id":   "<string>",
//	  "challenge_id":  "<string>",
//	  "pop_signature": "<base64url-encoded 64-byte Ed25519 signature>"
//	}
type TokenRequest struct {
	IdentityID   string `json:"identity_id"`
	ChallengeID  string `json:"challenge_id"`
	PoPSignature string `json:"pop_signature"` // base64url, 64 bytes
}

// TokenResponse is the JSON body returned by POST /auth/token.
//
//	{
//	  "token":      "<RS256 JWT>",
//	  "expires_in": 300
//	}
type TokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
}

// HandleToken implements POST /auth/token.
//
// Validates the EdDSA Proof-of-Possession over a previously issued challenge,
// then issues a short-lived RS256 JWT (TTL=300s).
//
// Error responses:
//   - 400  malformed request
//   - 401  unknown identity_id
//   - 403  missing / invalid PoP signature (TS-05)
func (a *AuthService) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TokenRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.IdentityID == "" || req.ChallengeID == "" || req.PoPSignature == "" {
		jsonError(w, "identity_id, challenge_id, and pop_signature are required", http.StatusBadRequest)
		return
	}

	// Look up the registered public key.
	a.identMu.RLock()
	pk, ok := a.identities[req.IdentityID]
	a.identMu.RUnlock()
	if !ok {
		jsonError(w, "unknown identity_id", http.StatusUnauthorized)
		return
	}

	// Consume the challenge (one-time use).
	a.challengeMu.Lock()
	challenge, exists := a.challenges[req.ChallengeID]
	if exists {
		delete(a.challenges, req.ChallengeID) // prevent replay
	}
	a.challengeMu.Unlock()
	if !exists {
		// Challenge not found or already used.
		jsonError(w, "challenge not found or already used", http.StatusForbidden)
		return
	}

	// Decode and verify the PoP signature.
	sigBytes, err := base64.RawURLEncoding.DecodeString(req.PoPSignature)
	if err != nil || len(sigBytes) != 64 {
		jsonError(w, "pop_signature must be base64url-encoded 64-byte Ed25519 signature", http.StatusForbidden)
		return
	}
	var sig ztsscrypto.Signature
	copy(sig[:], sigBytes)

	if err = ztsscrypto.VerifyPoP(pk, challenge, sig); err != nil {
		// TS-05: missing or invalid PoP → 403.
		jsonError(w, "proof-of-possession verification failed", http.StatusForbidden)
		return
	}

	// Issue the RS256 JWT.
	token, err := a.issueJWT(req.IdentityID)
	if err != nil {
		jsonError(w, "token issuance failed", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, TokenResponse{
		Token:     token,
		ExpiresIn: int(JWTTTL.Seconds()),
	})
}

// ── JWT issuance ──────────────────────────────────────────────────────────────

// jwtHeader is the fixed RS256 JWT header, base64url-encoded.
var jwtHeader = base64.RawURLEncoding.EncodeToString(
	[]byte(`{"alg":"RS256","typ":"JWT"}`),
)

// jwtPayload is the structure of the JWT payload claims.
type jwtPayload struct {
	Sub string `json:"sub"` // identity_id
	Iat int64  `json:"iat"` // issued-at (Unix seconds)
	Exp int64  `json:"exp"` // expires-at (Unix seconds) = iat + 300
	Jti string `json:"jti"` // unique token ID (replay prevention, TS-03)
}

// issueJWT signs a new RS256 JWT for sub with TTL = JWTTTL.
func (a *AuthService) issueJWT(sub string) (string, error) {
	now := time.Now().Unix()
	jti, err := randomBase64(16)
	if err != nil {
		return "", fmt.Errorf("jti generation: %w", err)
	}

	payload := jwtPayload{
		Sub: sub,
		Iat: now,
		Exp: now + int64(JWTTTL.Seconds()),
		Jti: jti,
	}

	payJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("payload marshal: %w", err)
	}
	payB64 := base64.RawURLEncoding.EncodeToString(payJSON)

	// Signing input: base64url(header) + "." + base64url(payload).
	signingInput := jwtHeader + "." + payB64
	digest := sha256.Sum256([]byte(signingInput))

	rawSig, err := rsa.SignPKCS1v15(rand.Reader, a.serverKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("RSA sign: %w", err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(rawSig)

	return signingInput + "." + sigB64, nil
}

// ── JWT parsing & verification (used by middleware) ───────────────────────────

// ParsedJWT holds the decoded, verified JWT claims.
type ParsedJWT struct {
	Subject string // "sub" claim = identity_id
	Jti     string // "jti" claim for replay detection (TS-03)
	Exp     int64  // Unix expiry timestamp
}

// VerifyJWT parses and verifies a compact RS256 JWT string.
//
// Returns ErrJWTExpired if exp < now (TF-06 / TS-03).
// Returns ErrJWTInvalid for any other failure (bad signature, wrong alg, etc.)
func (a *AuthService) VerifyJWT(tokenStr string) (*ParsedJWT, error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil, ErrJWTInvalid
	}

	// Verify header declares RS256.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrJWTInvalid
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err = json.Unmarshal(headerJSON, &hdr); err != nil || hdr.Alg != JWTAlg {
		return nil, fmt.Errorf("%w: algorithm must be RS256, got %q", ErrJWTInvalid, hdr.Alg)
	}

	// Verify RSA-PKCS1v15-SHA256 signature.
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrJWTInvalid
	}
	if err = rsa.VerifyPKCS1v15(a.ServerPubKey, crypto.SHA256, digest[:], sigBytes); err != nil {
		return nil, fmt.Errorf("%w: signature verification failed", ErrJWTInvalid)
	}

	// Decode payload claims.
	payJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrJWTInvalid
	}
	var claims jwtPayload
	if err = json.Unmarshal(payJSON, &claims); err != nil {
		return nil, ErrJWTInvalid
	}

	// Hard TTL check: exp − iat must not exceed 300 s (wiki/auth_requirements.md §JWT).
	if claims.Exp-claims.Iat > int64(JWTTTL.Seconds()) {
		return nil, fmt.Errorf("%w: TTL exceeds 300 s", ErrJWTInvalid)
	}

	// Expiry check (TF-06, TS-03).
	if time.Now().Unix() > claims.Exp {
		return nil, ErrJWTExpired
	}

	return &ParsedJWT{
		Subject: claims.Sub,
		Jti:     claims.Jti,
		Exp:     claims.Exp,
	}, nil
}

// MarkJTIUsed records a jti in the replay cache.  Returns ErrJWTReplay if
// the jti has already been seen (TS-03).
func (a *AuthService) MarkJTIUsed(jti string, exp int64) error {
	a.jtiMu.Lock()
	defer a.jtiMu.Unlock()

	// Evict expired entries to keep the cache bounded.
	now := time.Now().Unix()
	for k, expTime := range a.jtiCache {
		if now > expTime.Unix() {
			delete(a.jtiCache, k)
		}
	}

	if _, seen := a.jtiCache[jti]; seen {
		return ErrJWTReplay
	}
	a.jtiCache[jti] = time.Unix(exp, 0)
	return nil
}

// LookupIdentity returns the EdDSA public key for a registered identity_id.
// Returns (zero, false) if not found.
func (a *AuthService) LookupIdentity(id string) (ztsscrypto.IdentityPubKey, bool) {
	a.identMu.RLock()
	pk, ok := a.identities[id]
	a.identMu.RUnlock()
	return pk, ok
}

// ── Sentinel errors ───────────────────────────────────────────────────────────

var (
	// ErrJWTExpired is returned when the token's exp claim is in the past.
	// Maps to HTTP 401 (TF-06, TS-03).
	ErrJWTExpired = errors.New("ztss/api: JWT expired")

	// ErrJWTInvalid is returned for any JWT structural or signature error.
	// Maps to HTTP 401.
	ErrJWTInvalid = errors.New("ztss/api: JWT invalid")

	// ErrJWTReplay is returned when a jti has already been used (TS-03).
	// Maps to HTTP 401.
	ErrJWTReplay = errors.New("ztss/api: JWT replay detected")

	// ErrPoPMissing is returned when X-ZTSS-PoP or X-ZTSS-Challenge is absent.
	// Maps to HTTP 403 (TS-05).
	ErrPoPMissing = errors.New("ztss/api: Proof-of-Possession missing")

	// ErrPoPInvalid is returned when PoP signature verification fails.
	// Maps to HTTP 403 (TS-05).
	ErrPoPInvalid = errors.New("ztss/api: Proof-of-Possession invalid")
)

// ── HTTP helpers ──────────────────────────────────────────────────────────────

// jsonError writes a JSON error body with the specified HTTP status code.
// Format: { "error": "<message>" }
func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q}`+"\n", msg)
}

// writeJSON marshals v to JSON and writes it with status code.
func writeJSON(w http.ResponseWriter, code int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(b)
}

// randomBase64 returns n random bytes encoded as a base64url string (no padding).
func randomBase64(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
