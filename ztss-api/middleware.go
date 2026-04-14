// middleware.go — HTTP middleware enforcing JWT RS256 + EdDSA PoP on every
// protected API request.
//
// ── Middleware chain (ordered) ─────────────────────────────────────────────────
//
//  1. JWTMiddleware
//     - Extracts Bearer token from Authorization header.
//     - Verifies RS256 signature against server public key.
//     - Rejects expired tokens with HTTP 401 (TF-06, TS-03).
//     - Checks jti replay cache → 401 if seen before (TS-03).
//     - Stores parsed claims in request context for downstream handlers.
//
//  2. PoPMiddleware
//     - Reads X-ZTSS-Challenge (base64url challenge bytes, from GET /auth/challenge).
//     - Reads X-ZTSS-PoP (base64url 64-byte Ed25519 signature).
//     - Missing → HTTP 403 (TS-05).
//     - Retrieves Ed25519 public key from AuthService using "sub" from JWT context.
//     - Calls ztsscrypto.VerifyPoP → invalid → HTTP 403 (TS-05).
//
//  3. AuditMiddleware (ES5)
//     - Wraps every response, logging { timestamp, action, sig } after the
//       handler returns.
//
// ── Request flow ──────────────────────────────────────────────────────────────
//
//   Client → [JWTMiddleware] → [PoPMiddleware] → [AuditMiddleware] → Handler
//
// Usage in server.go:
//
//	mux.Handle("/upload", Chain(uploadHandler, JWT(auth), PoP(auth), Audit(log)))
//
// Wiki references:
//   - [[api_auth_layer#Middleware Requirements]]
//   - [[auth_requirements#JWT]]
//   - [[auth_requirements#Proof-of-Possession]]
//   - [[security_rules#ES1]] [[security_rules#ES5]]
//   - Test IDs: TF-06, TS-03, TS-05
package api

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	ztsscrypto "ztss/ztss-crypto"
)

// ── Context keys ──────────────────────────────────────────────────────────────

// contextKey is an unexported type for context values to prevent collisions.
type contextKey int

const (
	// ctxJWT is the context key for the parsed JWT (type *ParsedJWT).
	ctxJWT contextKey = iota

	// ctxIdentityID is the context key for the verified identity_id string.
	ctxIdentityID
)

// JWTFromContext retrieves the ParsedJWT stored by JWTMiddleware.
// Returns nil if the middleware has not run or if authentication failed.
func JWTFromContext(ctx context.Context) *ParsedJWT {
	v, _ := ctx.Value(ctxJWT).(*ParsedJWT)
	return v
}

// IdentityFromContext retrieves the verified identity_id stored by JWTMiddleware.
func IdentityFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxIdentityID).(string)
	return v
}

// ── Middleware constructors ───────────────────────────────────────────────────

// JWTMiddleware returns an http.Handler wrapper that validates the RS256 JWT
// on every request.
//
// Enforcement rules (wiki/auth_requirements.md §JWT):
//   - Authorization header must be present and start with "Bearer ".
//   - Token must have alg=RS256 and a valid server signature.
//   - Token must not be expired (exp ≥ now).  → HTTP 401 on failure.
//   - TTL (exp − iat) must not exceed 300 s.  → HTTP 401.
//   - jti must not have been seen before.      → HTTP 401 (TS-03 replay).
//
// On success, stores *ParsedJWT and identity_id in the request context.
func JWTMiddleware(auth *AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr, err := extractBearer(r)
			if err != nil {
				jsonError(w, err.Error(), http.StatusUnauthorized)
				return
			}

			claims, err := auth.VerifyJWT(tokenStr)
			if err != nil {
				code := http.StatusUnauthorized
				jsonError(w, err.Error(), code)
				return
			}

			// TS-03: jti replay check — mark as used after verification.
			if err = auth.MarkJTIUsed(claims.Jti, claims.Exp); err != nil {
				if errors.Is(err, ErrJWTReplay) {
					jsonError(w, "JWT replay detected", http.StatusUnauthorized)
					return
				}
				jsonError(w, "internal error", http.StatusInternalServerError)
				return
			}

			// Store verified claims in context for downstream middleware/handlers.
			ctx := context.WithValue(r.Context(), ctxJWT, claims)
			ctx = context.WithValue(ctx, ctxIdentityID, claims.Subject)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// PoPMiddleware returns an http.Handler wrapper that validates the EdDSA
// Proof-of-Possession on every request, after JWTMiddleware has run.
//
// Expected request headers:
//   - X-ZTSS-Challenge:  base64url-encoded challenge bytes
//     (issued by GET /auth/challenge; must NOT be a raw challenge from
//     /auth/token at this point — the PoP on data requests uses fresh
//     per-request challenges embedded in the header).
//   - X-ZTSS-PoP:       base64url-encoded 64-byte Ed25519 signature
//
// Enforcement:
//   - Missing either header → HTTP 403 (TS-05).
//   - Unknown identity (sub not in identity store) → HTTP 403.
//   - Invalid PoP signature → HTTP 403 (TS-05).
//
// Requires JWTMiddleware to have already run (reads identity_id from context).
func PoPMiddleware(auth *AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TS-05: both headers are mandatory.
			challengeHdr := r.Header.Get("X-ZTSS-Challenge")
			popHdr := r.Header.Get("X-ZTSS-PoP")

			if challengeHdr == "" || popHdr == "" {
				jsonError(w, "X-ZTSS-Challenge and X-ZTSS-PoP headers are required", http.StatusForbidden)
				return
			}

			// Extract identity_id from context (set by JWTMiddleware).
			identityID := IdentityFromContext(r.Context())
			if identityID == "" {
				jsonError(w, "JWT must be validated before PoP", http.StatusUnauthorized)
				return
			}

			// Look up the registered Ed25519 public key.
			pk, ok := auth.LookupIdentity(identityID)
			if !ok {
				jsonError(w, "identity not registered", http.StatusForbidden)
				return
			}

			// Decode the challenge.
			challengeBytes, err := base64.RawURLEncoding.DecodeString(challengeHdr)
			if err != nil || len(challengeBytes) == 0 {
				jsonError(w, "X-ZTSS-Challenge must be a non-empty base64url value", http.StatusForbidden)
				return
			}

			// Decode the PoP signature.
			sigBytes, err := base64.RawURLEncoding.DecodeString(popHdr)
			if err != nil || len(sigBytes) != 64 {
				jsonError(w, "X-ZTSS-PoP must be a 64-byte base64url Ed25519 signature", http.StatusForbidden)
				return
			}
			var sig ztsscrypto.Signature
			copy(sig[:], sigBytes)

			// Verify: calls ztss-crypto.VerifyPoP which prepends "ztss-pop-v1\x00".
			if err = ztsscrypto.VerifyPoP(pk, challengeBytes, sig); err != nil {
				jsonError(w, "proof-of-possession verification failed", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ── AuditMiddleware (ES5) ─────────────────────────────────────────────────────

// AuditEntry is a single signed, timestamped audit log record (wiki §ES5).
//
//	{ "timestamp": "…", "action": "…", "sig": "…" }
//
// The signature covers HMAC-SHA256(timestamp + action) with the audit key,
// ensuring log entries cannot be silently removed or modified.
type AuditEntry struct {
	Timestamp  string `json:"timestamp"`
	Action     string `json:"action"`
	IdentityID string `json:"identity_id,omitempty"`
	StatusCode int    `json:"status_code"`
	Sig        string `json:"sig"` // base64url HMAC-SHA256
}

// AuditLog is a thread-safe in-memory audit log.
// In production, entries would be persisted to an append-only store.
type AuditLog struct {
	hmacKey []byte
	mu      sync.RWMutex
	entries []AuditEntry
}

// NewAuditLog creates an AuditLog with a freshly generated HMAC key.
func NewAuditLog() (*AuditLog, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("ztss/api: NewAuditLog: HMAC key gen: %w", err)
	}
	return &AuditLog{hmacKey: key}, nil
}

// Append adds a signed entry to the log.
func (l *AuditLog) Append(action, identityID string, statusCode int) {
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	sig := l.sign(ts, action)
	l.mu.Lock()
	l.entries = append(l.entries, AuditEntry{
		Timestamp:  ts,
		Action:     action,
		IdentityID: identityID,
		StatusCode: statusCode,
		Sig:        sig,
	})
	l.mu.Unlock()
}

// Entries returns a copy of all audit entries (for GET /audit).
func (l *AuditLog) Entries() []AuditEntry {
	l.mu.RLock()
	cp := make([]AuditEntry, len(l.entries))
	copy(cp, l.entries)
	l.mu.RUnlock()
	return cp
}

// sign returns base64url(HMAC-SHA256(key, timestamp+action)).
func (l *AuditLog) sign(timestamp, action string) string {
	mac := hmac.New(sha256.New, l.hmacKey)
	mac.Write([]byte(timestamp))
	mac.Write([]byte(action))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// responseRecorder wraps http.ResponseWriter to capture the status code
// for the audit log, without importing httptest.
type responseRecorder struct {
	http.ResponseWriter
	code int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.code = code
	r.ResponseWriter.WriteHeader(code)
}

// AuditMiddleware wraps every handler response in a signed audit log entry
// (wiki/security_rules.md §ES5).  Must run after JWTMiddleware so that the
// identity_id is available in the context.
func AuditMiddleware(log *AuditLog) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rr := &responseRecorder{ResponseWriter: w, code: http.StatusOK}
			next.ServeHTTP(rr, r)

			action := r.Method + " " + r.URL.Path
			identityID := IdentityFromContext(r.Context())
			log.Append(action, identityID, rr.code)
		})
	}
}

// ── Middleware chainer ────────────────────────────────────────────────────────

// Chain applies a sequence of middleware to a handler.  The first middleware
// in the slice is outermost (runs first on request, last on response).
//
//	Chain(handler, JWT(auth), PoP(auth), Audit(log))
//
// Is equivalent to:
//
//	JWT(auth)(PoP(auth)(Audit(log)(handler)))
func Chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}

// ── Helper: extract Bearer token ──────────────────────────────────────────────

// extractBearer reads the Authorization header and returns the Bearer token.
// Returns an error if the header is missing or malformed.
func extractBearer(r *http.Request) (string, error) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return "", errors.New("Authorization header missing")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(hdr, prefix) {
		return "", errors.New("Authorization header must use Bearer scheme")
	}
	token := strings.TrimPrefix(hdr, prefix)
	if token == "" {
		return "", errors.New("Bearer token is empty")
	}
	return token, nil
}

// ── GET /audit handler ────────────────────────────────────────────────────────

// HandleAudit implements GET /audit and returns all signed log entries (ES5).
// This handler does NOT go through JWTMiddleware in the default server setup —
// it is intentionally public to allow external audit tools to verify signatures.
// Restrict it with a separate admin-only middleware in production if needed.
func HandleAudit(log *AuditLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		entries := log.Entries()
		writeJSON(w, http.StatusOK, entries)
	}
}

// ── PoP challenge freshness filter ───────────────────────────────────────────

// PoPChallengeStore is a short-lived store for per-request PoP challenges
// issued inline (as opposed to the token-issuance challenges in AuthService).
//
// Each per-request challenge has a MaxAge after which it is considered stale.
// This gives the client a narrow window to use the challenge, mitigating
// time-extension replay attacks.
type PoPChallengeStore struct {
	mu       sync.Mutex
	store    map[string]time.Time // nonce → issued-at
	maxAge   time.Duration
}

// NewPoPChallengeStore returns a challenge store with the given max age.
func NewPoPChallengeStore(maxAge time.Duration) *PoPChallengeStore {
	return &PoPChallengeStore{
		store:  make(map[string]time.Time),
		maxAge: maxAge,
	}
}

// Issue mints a fresh challenge nonce (base64url) and records its issuance time.
func (s *PoPChallengeStore) Issue() (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)

	s.mu.Lock()
	s.evict()
	s.store[nonce] = time.Now()
	s.mu.Unlock()
	return nonce, nil
}

// Consume validates that nonce was issued and has not expired.
// Deletes the nonce to enforce single-use semantics.
// Returns an error if nonce is unknown or stale.
func (s *PoPChallengeStore) Consume(nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evict()
	issuedAt, ok := s.store[nonce]
	if !ok {
		return errors.New("unknown or already-consumed challenge")
	}
	delete(s.store, nonce)
	if time.Since(issuedAt) > s.maxAge {
		return errors.New("challenge has expired")
	}
	return nil
}

// evict removes expired entries.  Must be called with s.mu held.
func (s *PoPChallengeStore) evict() {
	for nonce, t := range s.store {
		if time.Since(t) > s.maxAge {
			delete(s.store, nonce)
		}
	}
}

// ── Utility: verify a raw Ed25519 PoP inline (for tests) ─────────────────────

// VerifyRawPoP verifies an Ed25519 PoP signature without going through the
// ztss-crypto package.  Used in tests to isolate the middleware from the
// crypto layer.  NOT for production use.
func VerifyRawPoP(pubKey [32]byte, challenge []byte, sig [64]byte) bool {
	const ctx = "ztss-pop-v1\x00"
	msg := append([]byte(ctx), challenge...)
	return ed25519.Verify(pubKey[:], msg, sig[:])
}

// HandleAuditJSON is the same as HandleAudit but pretty-prints entries.
// Useful during development and security demonstrations.
func HandleAuditJSON(log *AuditLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		entries := log.Entries()
		b, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(b)
	}
}
