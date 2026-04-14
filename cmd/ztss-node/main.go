package main

// cmd/ztss-node/main.go — ZTSS combined node+API server binary.
//
// Reads configuration from environment variables (set by docker-compose.yml)
// that mirror the YAML fields in wiki/network_layer.md:
//
//   ZTSS_ADDR            TCP listen address for the P2P node      (default: :7001)
//   ZTSS_API_ADDR        TCP listen address for the REST API       (default: :8080)
//   ZTSS_STORAGE_DIR     Directory for FileSystem BlockStore        (default: /data)
//   ZTSS_CAPACITY        Max bytes for storage (0 = unlimited)     (default: 0)
//   ZTSS_SEEDS           Comma-separated peer seed addresses        (default: "")
//   ZTSS_INSECURE_TLS    "true" to disable peer cert verification   (default: false)
//
// Startup:
//   1. Parse env → NodeConfig + API address.
//   2. Create storage.FileSystemStore at ZTSS_STORAGE_DIR.
//   3. Wrap it in storeAdapter (bridges storage.CID ↔ [32]byte).
//   4. Start P2P node (ztss-node package).
//   5. Start REST API (ztss-api package).
//   6. Block until SIGTERM/SIGINT; gracefully drain both.

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	nodeapi  "ztss/ztss-api"
	"ztss/ztss-node"
	"ztss/ztss-storage"
)

// ── storeAdapter ──────────────────────────────────────────────────────────────

// storeAdapter wraps *storage.FileSystemStore and exposes the [32]byte CID
// type expected by both node.BlockStore and api.FileStore.
//
// storage.CID is defined as `type CID [32]byte`; while the underlying memory
// layout is identical to [32]byte, Go's type system treats them as distinct
// types for interface satisfaction.  A thin adapter is the idiomatic fix.
type storeAdapter struct {
	inner *storage.FileSystemStore
}

func (a storeAdapter) Put(cid [32]byte, data []byte) error {
	return a.inner.Put(storage.CID(cid), data)
}

func (a storeAdapter) Get(cid [32]byte) ([]byte, error) {
	return a.inner.Get(storage.CID(cid))
}

func (a storeAdapter) Has(cid [32]byte) bool {
	return a.inner.Has(storage.CID(cid))
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[ztss] ")

	// ── Configuration from environment ────────────────────────────────────────
	nodeAddr   := envOrDefault("ZTSS_ADDR", ":7001")
	apiAddr    := envOrDefault("ZTSS_API_ADDR", ":8080")
	storageDir := envOrDefault("ZTSS_STORAGE_DIR", "/data")
	capStr     := envOrDefault("ZTSS_CAPACITY", "0")
	seedsStr   := envOrDefault("ZTSS_SEEDS", "")
	insecure   := os.Getenv("ZTSS_INSECURE_TLS") == "true"

	capacity, err := strconv.ParseInt(capStr, 10, 64)
	if err != nil {
		log.Fatalf("ZTSS_CAPACITY must be an integer: %v", err)
	}

	seeds := parseSeedList(seedsStr)

	// ── Storage backend ────────────────────────────────────────────────────────
	if err = os.MkdirAll(storageDir, 0750); err != nil {
		log.Fatalf("create storage dir %q: %v", storageDir, err)
	}
	fsStore, err := storage.NewFileSystemStore(storageDir)
	if err != nil {
		log.Fatalf("FileSystemStore at %q: %v", storageDir, err)
	}
	// Wrap so both packages receive a [32]byte-keyed BlockStore.
	adapted := storeAdapter{inner: fsStore}
	log.Printf("storage: FileSystemStore at %s (capacity=%d bytes)", storageDir, capacity)

	// ── Root context (SIGTERM / SIGINT) ────────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// ── P2P node ───────────────────────────────────────────────────────────────
	nodeCfg := node.NodeConfig{
		Addr:            nodeAddr,
		Seeds:           seeds,
		StorageCapacity: capacity,
		InsecureTLS:     insecure,
	}
	n, err := node.NewNode(nodeCfg, adapted)
	if err != nil {
		log.Fatalf("NewNode: %v", err)
	}
	log.Printf("node: P2P listening on %s (seeds: %v)", nodeAddr, seeds)

	go func() {
		if runErr := n.Run(ctx); runErr != nil {
			log.Printf("node: stopped: %v", runErr)
		}
	}()

	// ── REST API server ────────────────────────────────────────────────────────
	authSvc, err := nodeapi.NewAuthService()
	if err != nil {
		log.Fatalf("NewAuthService: %v", err)
	}
	auditLog, err := nodeapi.NewAuditLog()
	if err != nil {
		log.Fatalf("NewAuditLog: %v", err)
	}

	// Pass the same adapted store so REST uploads feed directly into the node's
	// BlockStore and are immediately available for inter-node replication.
	apiSrv := nodeapi.NewServer(authSvc, auditLog, adapted)

	httpSrv := &http.Server{
		Addr:         apiAddr,
		Handler:      apiSrv.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("api: REST listening on %s", apiAddr)
		if serveErr := httpSrv.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
			log.Printf("api: %v", serveErr)
		}
	}()

	// ── Block until shutdown signal ───────────────────────────────────────────
	<-ctx.Done()
	log.Println("received shutdown signal — draining …")

	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = httpSrv.Shutdown(shutCtx); err != nil {
		log.Printf("api shutdown: %v", err)
	}
	n.WaitStopped()
	log.Println("shutdown complete")
}

// envOrDefault returns the value of the environment variable key, or def if unset.
func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// parseSeedList splits a comma-separated list of addresses into a string slice.
func parseSeedList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, addr := range strings.Split(s, ",") {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			out = append(out, addr)
		}
	}
	return out
}
