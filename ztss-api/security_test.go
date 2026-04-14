package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"fmt"

	ztsscrypto "ztss/ztss-crypto"
	"ztss/ztss-storage"
)

// fsStoreAdapter bridges the storage.CID type difference (like in main.go).
type fsStoreAdapter struct {
	inner *storage.FileSystemStore
}

func (a fsStoreAdapter) Put(cid [32]byte, data []byte) error {
	return a.inner.Put(storage.CID(cid), data)
}
func (a fsStoreAdapter) Get(cid [32]byte) ([]byte, error) {
	return a.inner.Get(storage.CID(cid))
}
func (a fsStoreAdapter) Has(cid [32]byte) bool {
	return a.inner.Has(storage.CID(cid))
}

// setupFSTestEnv creates an api test environment backed by an actual FileSystemStore
// so we can test adversarial writes directly to the disk.
func setupFSTestEnv(t *testing.T) (*testEnv, string) {
	t.Helper()

	auth, err := NewAuthService()
	if err != nil {
		t.Fatalf("NewAuthService: %v", err)
	}
	auditLog, err := NewAuditLog()
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}

	tempDir := t.TempDir()
	fsStore, err := storage.NewFileSystemStore(tempDir)
	if err != nil {
		t.Fatalf("NewFileSystemStore: %v", err)
	}
	adaptedStore := fsStoreAdapter{inner: fsStore}

	srv := NewServer(auth, auditLog, adaptedStore)
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

	env := &testEnv{
		auth:       auth,
		auditLog:   auditLog,
		tsrv:       tsrv,
		identityID: regResp.IdentityID,
		sk:         sk,
		pk:         pk,
	}
	return env, tempDir
}

// ── Adversarial Matrix Tests ──────────────────────────────────────────────────

// 1. Send an expired JWT (Expect 401 - TS-03)
func TestSecurity_ExpiredJWT_TS03(t *testing.T) {
	env, _ := setupFSTestEnv(t)

	// Create a JWT that expired 10 minutes ago, but has a perfectly valid signature.
	expiredToken := craftExpiredJWT(t, env.auth)

	// Even with a valid PoP, the expired JWT MUST trigger a 401.
	chalReq := doRequest(t, env.tsrv, http.MethodGet, "/auth/challenge", "", nil)
	chalReq.Body.Close() // Best effort
	
	// Create headers to upload
	freshChallenge := make([]byte, 32)
	popSig, _ := ztsscrypto.ProofOfPossession(env.sk, freshChallenge)

	headers := map[string]string{
		"Authorization":    "Bearer " + expiredToken,
		"X-ZTSS-Challenge": base64.RawURLEncoding.EncodeToString(freshChallenge),
		"X-ZTSS-PoP":       base64.RawURLEncoding.EncodeToString(popSig[:]),
		"Content-Type":     "application/json",
	}

	resp := doRequest(t, env.tsrv, http.MethodPost, "/upload", `{"root_cid":"fake","chunks":[]}`, headers)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("TS-03 violation: Expected 401 Unauthorized for expired JWT, got %d", resp.StatusCode)
	}
}

// 2. Send a valid JWT without the EdDSA PoP (Expect 403 - TS-05)
func TestSecurity_MissingPoP_TS05(t *testing.T) {
	env, _ := setupFSTestEnv(t)
	
	validToken := craftLongLivedJWT(t, env.auth, 300)

	// Valid JWT, but completely missing PoP headers.
	headers := map[string]string{
		"Authorization": "Bearer " + validToken,
		"Content-Type":  "application/json",
	}

	resp := doRequest(t, env.tsrv, http.MethodPost, "/upload", `{"root_cid":"fake","chunks":[]}`, headers)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("TS-05 violation: Expected 403 Forbidden for missing PoP, got %d", resp.StatusCode)
	}
}

// 3. Modify 1 byte of a stored chunk on disk and attempt a download (Expect Merkle reject - TS-02)
func TestSecurity_MerkleRejectOnTamperedDisk_TS02(t *testing.T) {
	env, diskDir := setupFSTestEnv(t)

	// 1. Construct a valid file and upload it.
	chunkData := []byte("adversarial-target-data-payload")
	cid := sha256.Sum256(chunkData)
	cidHex := hex.EncodeToString(cid[:])

	// The MerkleRoot of a single chunk is just the chunk's CID.
	hashes := [][32]byte{cid}
	root, err := storage.MerkleRootFromHashes(hashes)
	if err != nil {
		t.Fatalf("Merkle calculation: %v", err)
	}
	rootCIDhex := hex.EncodeToString(root[:])

	body := buildUploadBody(t, cid, chunkData)
	headers := env.authHeaders(t)

	upResp := doRequest(t, env.tsrv, http.MethodPost, "/upload", body, headers)
	if upResp.StatusCode != http.StatusCreated {
		t.Fatalf("Upload failed: %d", upResp.StatusCode)
	}
	upResp.Body.Close()

	// 2. Locate the chunk on disk (FileSystemStore writes to <diskDir>/<hex>).
	chunkPath := filepath.Join(diskDir, cidHex)

	diskBytes, err := os.ReadFile(chunkPath)
	if err != nil {
		t.Fatalf("Could not locate stored chunk on disk: %v", err)
	}

	// 3. TAMPER WITH THE DISK DIRECTLY.
	// We represent a malicious storage admin flipping a bit to ruin the cipher payload.
	diskBytes[5] ^= 0xFF 
	if err := os.WriteFile(chunkPath, diskBytes, 0644); err != nil {
		t.Fatalf("Could not poison chunk on disk: %v", err)
	}

	// 4. Client attempts a download. The server's Merkle verification MUST catch the silent disk corruption.
	downHeaders := env.authHeaders(t)
	downResp := doRequest(t, env.tsrv, http.MethodGet, "/download/"+rootCIDhex, "", downHeaders)
	defer downResp.Body.Close()

	// The download should fail as the server realizes the blocks read from disk
	// do not hash up to the requested Merkle Root.
	if downResp.StatusCode != http.StatusInternalServerError {
		bz, _ := io.ReadAll(downResp.Body)
		t.Fatalf("TS-02 violation: Server did not reject tampered Merkle structure. Got status %d. Body: %s", downResp.StatusCode, bz)
	}

	respBytes, _ := io.ReadAll(downResp.Body)
	if !bytes.Contains(respBytes, []byte("storage corruption detected")) {
		t.Errorf("Expected corruption detection string in error body, got: %s", string(respBytes))
	}
}
