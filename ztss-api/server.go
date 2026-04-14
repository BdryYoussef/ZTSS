// server.go — ZTSS REST API server.
//
// Endpoints (wiki/api_auth_layer.md §REST Endpoints):
//
//   POST /auth/register    → { public_key, identity_id }
//   GET  /auth/challenge   → { challenge_id, challenge }
//   POST /auth/token       → { token, expires_in:300 }
//   POST /upload           → { root_cid, chunks_count }      [JWT + PoP required]
//   GET  /download/:cid    → stream ciphertext               [JWT + PoP required]
//   POST /share            → { re_key, delegated_cid }       [JWT + PoP required]
//   GET  /audit            → [{ timestamp, action, sig }]    [public]
//
// Middleware chain on protected endpoints (JWT first, PoP second, Audit last):
//
//   Request → JWTMiddleware → PoPMiddleware → AuditMiddleware → Handler
//
// ── Security constraints ──────────────────────────────────────────────────────
//
//   ES1  : JWTMiddleware + PoPMiddleware run on every protected route.
//   ES2  : /upload accepts only ciphertext (enforced by documentation + schema).
//          The server does NOT decrypt; it passes opaque bytes to the BlockStore.
//   ES5  : AuditMiddleware logs every hit with a signed, timestamped entry.
//   TS-03: JWTMiddleware rejects replayed JTIs → 401.
//   TS-05: PoPMiddleware rejects missing PoP   → 403.
//
// ── Storage integration ───────────────────────────────────────────────────────
//
//   The server is injected with a FileStore (wiki §BlockStore Backends).
//   In production: storage.NewFileSystemStore(path).
//   In tests:     storage.NewInMemoryStore() or the lightweight apiStore adapter.
//
// ── No relational DB ─────────────────────────────────────────────────────────
//
//   Per wiki/database_schema.md: all persistence is content-addressed via
//   BlockStore.  The file catalogue (root_cid → chunks) is kept in a thread-safe
//   in-process map.  ReKeys are also kept in-process (the wiki schema does not
//   specify a durable ReKey store).
//
// Wiki references:
//   - [[api_auth_layer#REST Endpoints]]
//   - [[api_auth_layer#Middleware Requirements]]
//   - [[database_schema]]
//   - [[security_rules#ES2]] (nodes store only ciphertext)
package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"ztss/ztss-storage"
)

// ── Storage interface ─────────────────────────────────────────────────────────

// FileStore is the local storage interface used by the API server.
// It mirrors storage.BlockStore (ztss-storage) to avoid an import cycle;
// any *storage.InMemoryStore or *storage.FileSystemStore satisfies it.
type FileStore interface {
	Put(cid [32]byte, data []byte) error
	Get(cid [32]byte) ([]byte, error)
	Has(cid [32]byte) bool
}

// ── File catalogue ────────────────────────────────────────────────────────────

// FileMeta records the metadata for an uploaded file (its Merkle root and the
// ordered list of chunk CIDs).  Stored server-side to service /download/:cid.
type FileMeta struct {
	RootCID     string   `json:"root_cid"`     // 64-char hex
	ChunksCount int      `json:"chunks_count"`
	ChunkCIDs   []string `json:"chunk_cids"`   // hex strings, ordered
	OwnerID     string   `json:"owner_id"`     // identity_id of uploader
}

// ReKeyRecord associates a re-encryption key with a delegated file root CID.
type ReKeyRecord struct {
	ReKey        []byte // 80 bytes (wiki/database_schema.md §Re-Encryption Key)
	DelegatedCID string // hex MerkleRoot
	DelegatedBy  string // identity_id of the delegating user
}

// fileCatalogue is a thread-safe map of rootCID (hex) → FileMeta.
type fileCatalogue struct {
	mu    sync.RWMutex
	files map[string]*FileMeta
}

func newFileCatalogue() *fileCatalogue {
	return &fileCatalogue{files: make(map[string]*FileMeta)}
}

func (c *fileCatalogue) Put(rootCID string, meta *FileMeta) {
	c.mu.Lock()
	c.files[rootCID] = meta
	c.mu.Unlock()
}

func (c *fileCatalogue) Get(rootCID string) (*FileMeta, bool) {
	c.mu.RLock()
	m, ok := c.files[rootCID]
	c.mu.RUnlock()
	return m, ok
}

// reKeyStore is a thread-safe store of identity_id → []ReKeyRecord.
type reKeyStore struct {
	mu   sync.RWMutex
	keys map[string][]ReKeyRecord // identity_id → delegations
}

func newReKeyStore() *reKeyStore {
	return &reKeyStore{keys: make(map[string][]ReKeyRecord)}
}

func (s *reKeyStore) Add(identityID string, rk ReKeyRecord) {
	s.mu.Lock()
	s.keys[identityID] = append(s.keys[identityID], rk)
	s.mu.Unlock()
}

// ── Server ────────────────────────────────────────────────────────────────────

// Server is the ZTSS REST API server.
type Server struct {
	auth     *AuthService
	auditLog *AuditLog
	store    FileStore

	catalogue *fileCatalogue
	reKeys    *reKeyStore

	mux      *http.ServeMux
	listener net.Listener
	srv      *http.Server
}

// NewServer constructs a Server.  Call ListenAndServe or Serve to start it.
func NewServer(auth *AuthService, auditLog *AuditLog, store FileStore) *Server {
	s := &Server{
		auth:      auth,
		auditLog:  auditLog,
		store:     store,
		catalogue: newFileCatalogue(),
		reKeys:    newReKeyStore(),
		mux:       http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

// ListenAndServe starts the server on addr.  Blocks until the context is done.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("ztss/api: ListenAndServe: %w", err)
	}
	return s.Serve(ctx, ln)
}

// Serve starts the server with an existing listener.  Mostly used in tests.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.listener = ln
	s.srv = &http.Server{
		Handler:      s.mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- s.srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

// Addr returns the server's listening address (useful in tests with ":0").
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// Handler returns the http.Handler for use in httptest.NewServer.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// ── Route registration ────────────────────────────────────────────────────────

// registerRoutes wires all endpoints to their handlers.
//
// Protected routes use the three-layer middleware chain:
//
//	Chain(handler, JWTMiddleware(auth), PoPMiddleware(auth), AuditMiddleware(auditLog))
func (s *Server) registerRoutes() {
	jwt  := JWTMiddleware(s.auth)
	pop  := PoPMiddleware(s.auth)
	audit := AuditMiddleware(s.auditLog)

	// ── Auth (public — no middleware) ─────────────────────────────────────
	s.mux.HandleFunc("/auth/register", s.auth.HandleRegister)
	s.mux.HandleFunc("/auth/challenge", s.auth.HandleChallenge)
	s.mux.HandleFunc("/auth/token", s.auth.HandleToken)

	// ── Protected endpoints ───────────────────────────────────────────────
	s.mux.Handle("/upload",
		Chain(http.HandlerFunc(s.handleUpload), jwt, pop, audit))

	s.mux.Handle("/download/",
		Chain(http.HandlerFunc(s.handleDownload), jwt, pop, audit))

	s.mux.Handle("/share",
		Chain(http.HandlerFunc(s.handleShare), jwt, pop, audit))

	// ── Audit log (public read — signatures are self-validating, ES5) ─────
	s.mux.Handle("/audit", HandleAuditJSON(s.auditLog))
}

// ── POST /upload ──────────────────────────────────────────────────────────────

// UploadRequest is the JSON body of POST /upload.
//
//	{
//	  "root_cid":    "<64-char hex MerkleRoot>",
//	  "chunks":      [{ "index": 0, "cid": "<hex>", "data": "<base64>" }, …]
//	}
//
// ES2: clients are responsible for encrypting data before upload.  The server
// stores whatever bytes it receives — it never decrypts.
type UploadRequest struct {
	RootCID string        `json:"root_cid"`
	Chunks  []ChunkUpload `json:"chunks"`
}

// ChunkUpload is a single chunk in an upload batch.
type ChunkUpload struct {
	Index uint64 `json:"index"`
	CID   string `json:"cid"`  // 64-char hex (SHA-256)
	Data  string `json:"data"` // base64url-encoded ciphertext
}

// UploadResponse is returned by POST /upload.
//
//	{ "root_cid": "<hex>", "chunks_count": <int> }
type UploadResponse struct {
	RootCID     string `json:"root_cid"`
	ChunksCount int    `json:"chunks_count"`
}

// handleUpload implements POST /upload.
//
// Steps:
//  1. Decode JSON body.
//  2. For each chunk: decode data, recompute SHA-256, verify == declared CID (TS-02).
//  3. BlockStore.Put(cid, data) for each chunk.
//  4. Record file metadata in the catalogue.
//  5. Return { root_cid, chunks_count }.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req UploadRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 512*1024*1024)).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.RootCID == "" || len(req.Chunks) == 0 {
		jsonError(w, "root_cid and at least one chunk are required", http.StatusBadRequest)
		return
	}

	chunkCIDs := make([]string, len(req.Chunks))

	for i, ch := range req.Chunks {
		// Decode the declared CID.
		cidHex, err := hex.DecodeString(ch.CID)
		if err != nil || len(cidHex) != 32 {
			jsonError(w, fmt.Sprintf("chunk %d: cid must be 64-char hex", i), http.StatusBadRequest)
			return
		}
		var declaredCID [32]byte
		copy(declaredCID[:], cidHex)

		// Decode chunk data.
		data, err := base64.StdEncoding.DecodeString(ch.Data)
		if err != nil {
			// Try RawURL as a fallback (clients may omit padding).
			data, err = base64.RawURLEncoding.DecodeString(ch.Data)
			if err != nil {
				jsonError(w, fmt.Sprintf("chunk %d: data is not valid base64", i), http.StatusBadRequest)
				return
			}
		}

		// TS-02: verify SHA-256(data) == declared CID before storing.
		import_sha256 := computeSHA256(data)
		if import_sha256 != declaredCID {
			jsonError(w, fmt.Sprintf("chunk %d: CID mismatch — SHA-256(data) does not equal declared CID", i), http.StatusBadRequest)
			return
		}

		// ES2: the server stores ciphertext opaquely (no decrypt).
		if err = s.store.Put(declaredCID, data); err != nil {
			jsonError(w, fmt.Sprintf("chunk %d: storage error: %v", i, err), http.StatusInternalServerError)
			return
		}
		chunkCIDs[i] = ch.CID
	}

	// Record file descriptor in the catalogue.
	ownerID := IdentityFromContext(r.Context())
	s.catalogue.Put(req.RootCID, &FileMeta{
		RootCID:     req.RootCID,
		ChunksCount: len(req.Chunks),
		ChunkCIDs:   chunkCIDs,
		OwnerID:     ownerID,
	})

	writeJSON(w, http.StatusCreated, UploadResponse{
		RootCID:     req.RootCID,
		ChunksCount: len(req.Chunks),
	})
}

// ── GET /download/:cid ────────────────────────────────────────────────────────

// handleDownload implements GET /download/:cid.
//
// The :cid path parameter is the MerkleRoot (root_cid) of the file, *not* an
// individual chunk CID.  The server looks up all chunk CIDs from the catalogue
// and streams them in order as a flat JSON array:
//
//	[{ "index": 0, "cid": "<hex>", "data": "<base64>" }, …]
//
// ES2: data is returned as-is (ciphertext); the client decrypts.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rootCIDhex := strings.TrimPrefix(r.URL.Path, "/download/")
	if rootCIDhex == "" {
		jsonError(w, "cid path parameter is required", http.StatusBadRequest)
		return
	}

	meta, ok := s.catalogue.Get(rootCIDhex)
	if !ok {
		jsonError(w, "file not found", http.StatusNotFound)
		return
	}

	// Stream all chunks as a JSON array.
	type ChunkDownload struct {
		Index int    `json:"index"`
		CID   string `json:"cid"`
		Data  string `json:"data"` // base64
	}

	results := make([]ChunkDownload, 0, len(meta.ChunkCIDs))
	hashes := make([][32]byte, 0, len(meta.ChunkCIDs))

	for i, cidHex := range meta.ChunkCIDs {
		cidBytes, err := hex.DecodeString(cidHex)
		if err != nil {
			jsonError(w, fmt.Sprintf("catalogue corruption: chunk %d has invalid CID", i), http.StatusInternalServerError)
			return
		}
		var cid [32]byte
		copy(cid[:], cidBytes)

		data, err := s.store.Get(cid)
		if err != nil {
			jsonError(w, fmt.Sprintf("chunk %d not found in store", i), http.StatusNotFound)
			return
		}
		
		// TS-02: Hash the actual data read from disk to reconstruct the Merkle leaf.
		actualCID := computeSHA256(data)

		results = append(results, ChunkDownload{
			Index: i,
			CID:   cidHex,
			Data:  base64.StdEncoding.EncodeToString(data),
		})
		hashes = append(hashes, actualCID)
	}

	// Verify the Merkle Root integrity before streaming back (requested by user).
	calculatedRoot, err := storage.MerkleRootFromHashes(hashes)
	if err != nil {
		jsonError(w, fmt.Sprintf("merkle tree error: %v", err), http.StatusInternalServerError)
		return
	}
	if hex.EncodeToString(calculatedRoot[:]) != rootCIDhex {
		jsonError(w, "storage corruption detected: chunks do not match requested Merkle root", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, results)
}

// ── POST /share ───────────────────────────────────────────────────────────────

// ShareRequest is the JSON body of POST /share.
//
//	{
//	  "root_cid":       "<hex>",          // file to delegate
//	  "delegatee_id":   "<identity_id>",  // recipient identity
//	  "re_key":         "<base64>",       // 80-byte ReKey from ztss-crypto.ReKeyGen
//	}
//
// The re-encryption key is computed CLIENT-SIDE by the owner (wiki §Proxy
// Re-Encryption).  The server stores the re-key association for future
// /download calls by the delegatee.
type ShareRequest struct {
	RootCID     string `json:"root_cid"`
	DelegateeID string `json:"delegatee_id"`
	ReKey       string `json:"re_key"` // base64, 80 bytes
}

// ShareResponse is returned by POST /share.
//
//	{ "re_key": "<base64>", "delegated_cid": "<hex>" }
type ShareResponse struct {
	ReKey        string `json:"re_key"`
	DelegatedCID string `json:"delegated_cid"`
}

// handleShare implements POST /share.
//
// Validates the re-key length (must be exactly 80 bytes, wiki §ReKey Wire Format)
// and stores the delegation record in the reKeyStore.
func (s *Server) handleShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ShareRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.RootCID == "" || req.DelegateeID == "" || req.ReKey == "" {
		jsonError(w, "root_cid, delegatee_id, and re_key are required", http.StatusBadRequest)
		return
	}

	// Verify the file exists in the catalogue.
	if _, ok := s.catalogue.Get(req.RootCID); !ok {
		jsonError(w, "root_cid not found — upload the file first", http.StatusNotFound)
		return
	}

	// Decode and validate the re-key (must be exactly 80 bytes, wiki §ReKey).
	rkBytes, err := base64.StdEncoding.DecodeString(req.ReKey)
	if err != nil {
		rkBytes, err = base64.RawURLEncoding.DecodeString(req.ReKey)
	}
	if err != nil || len(rkBytes) != 80 {
		jsonError(w, "re_key must be base64-encoded 80-byte ReKey", http.StatusBadRequest)
		return
	}

	delegatorID := IdentityFromContext(r.Context())
	s.reKeys.Add(req.DelegateeID, ReKeyRecord{
		ReKey:        rkBytes,
		DelegatedCID: req.RootCID,
		DelegatedBy:  delegatorID,
	})

	writeJSON(w, http.StatusCreated, ShareResponse{
		ReKey:        req.ReKey,
		DelegatedCID: req.RootCID,
	})
}

// ── Compile-time interface check ──────────────────────────────────────────────

// Ensure *Server satisfies http.Handler without importing net/http/httptest.
var _ http.Handler = (*http.ServeMux)(nil)

// ── Internal helpers ──────────────────────────────────────────────────────────

// computeSHA256 returns SHA-256(data) as a [32]byte.
// Used by handleUpload to verify chunk CID integrity before storage (TS-02).
func computeSHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}
