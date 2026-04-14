// node.go — ZTSS TCP server with one goroutine per connection.
//
// Responsibilities:
//   - Bind a TLS 1.3 listener on the configured address (TS-01 / ES3).
//   - Accept inbound connections and hand each off to a per-connection goroutine.
//   - Dispatch incoming messages to the correct handler based on the wire header
//     Type byte (0x01–0x05).
//   - Integrate with Discoverer (discovery.go) to register incoming peers and
//     respond to PING/PONG heartbeats.
//   - Integrate with the transfer layer (transfer.go) for STORE/GET/ANNOUNCE.
//
// Security constraints enforced here:
//   ES3: TLS 1.3 MinVersion; the plain net.Conn is never handed to handlers.
//   ES2: Handlers never inspect plaintext payload semantics; the storage layer
//        enforces ciphertext-only storage.
//
// Wiki references:
//   - [[network_layer#Node Architecture]]
//   - [[network_layer#Binary Wire Protocol]]
//   - [[network_layer#Transport Security]]
package node

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ── NodeConfig ────────────────────────────────────────────────────────────────

// NodeConfig carries all node startup parameters.
// Fields map 1:1 to the YAML configuration keys in wiki/network_layer.md.
type NodeConfig struct {
	// Addr is the TCP address to listen on, e.g. ":7001".
	Addr string

	// Seeds is the list of seed-node addresses used for bootstrap
	// (wiki/network_layer.md §Discovery Protocol).
	Seeds []string

	// StorageCapacity is the maximum bytes this node may store.
	// Transfer handlers reject STORE messages that would exceed this.
	StorageCapacity int64

	// TLSCert is the TLS 1.3 certificate for this node.
	// If zero-value, GenerateSelfSignedCert is called automatically
	// (development / integration test mode).
	TLSCert *tls.Certificate

	// InsecureTLS disables peer-certificate verification.
	// Must be false in production (TS-01).
	InsecureTLS bool

	// Heartbeat controls ping/pong timing.
	// If zero-value, DefaultHeartbeatConfig is used.
	Heartbeat HeartbeatConfig
}

// ── Node ─────────────────────────────────────────────────────────────────────

// Node is a single ZTSS storage node: it combines the TCP listener, the
// discovery/heartbeat subsystem, and the transfer handler into one struct.
//
// Typical lifecycle:
//
//	n, err := NewNode(cfg, store)
//	ctx, cancel := context.WithCancel(context.Background())
//	go n.Run(ctx)          // blocks until ctx is cancelled
//	// … wait for SIGTERM …
//	cancel()
//	n.WaitStopped()
type Node struct {
	cfg      NodeConfig
	store    BlockStore     // chunk storage backend
	transfer *TransferLayer // STORE/GET/ANNOUNCE handlers

	discoverer *Discoverer    // bootstrap + heartbeat
	listener   net.Listener   // TLS 1.3 listener

	logger   *log.Logger
	wg       sync.WaitGroup
	stopped  atomic.Bool    // set to true when Run returns
}

// NewNode constructs a Node.  It does NOT start listening yet (call Run).
//
//   - cfg:   node configuration (see NodeConfig).
//   - store: the BlockStore used to persist chunks.  Use storage.NewInMemoryStore()
//     for tests or storage.NewFileSystemStore(path) for production.
func NewNode(cfg NodeConfig, store BlockStore) (*Node, error) {
	// ── TLS certificate ────────────────────────────────────────────────────
	var cert tls.Certificate
	if cfg.TLSCert != nil {
		cert = *cfg.TLSCert
	} else {
		host, _, err := net.SplitHostPort(cfg.Addr)
		if err != nil || host == "" {
			host = "localhost"
		}
		cert, err = GenerateSelfSignedCert(host)
		if err != nil {
			return nil, fmt.Errorf("node: NewNode: self-signed cert: %w", err)
		}
	}

	// ── Heartbeat config ───────────────────────────────────────────────────
	hbCfg := cfg.Heartbeat
	if hbCfg.Interval == 0 {
		hbCfg = DefaultHeartbeatConfig
	}

	// ── TLS client config (for outgoing dials in Discoverer) ──────────────
	tlsClientCfg := tlsClientConfig(
		&cert,
		nil,              // no cluster CA in dev mode
		cfg.InsecureTLS,  // false in production
	)

	// ── Discoverer ─────────────────────────────────────────────────────────
	discoverer := NewDiscoverer(cfg.Addr, tlsClientCfg, hbCfg)

	// ── TLS server config ──────────────────────────────────────────────────
	serverTLSCfg := tlsServerConfig(cert)

	// ── TLS listener ──────────────────────────────────────────────────────
	ln, err := tls.Listen("tcp", cfg.Addr, serverTLSCfg)
	if err != nil {
		return nil, fmt.Errorf("node: NewNode: listen %s: %w", cfg.Addr, err)
	}

	// ── Transfer layer ─────────────────────────────────────────────────────
	transfer := NewTransferLayer(store, discoverer.Table(), cfg.StorageCapacity)

	logger := log.New(log.Writer(), fmt.Sprintf("[node %s] ", cfg.Addr), log.LstdFlags)

	return &Node{
		cfg:        cfg,
		store:      store,
		transfer:   transfer,
		discoverer: discoverer,
		listener:   ln,
		logger:     logger,
	}, nil
}

// Addr returns the address this node is listening on (resolved, with port).
func (n *Node) Addr() string {
	return n.listener.Addr().String()
}

// Table returns the routing table (for tests and the transfer layer).
func (n *Node) Table() *RoutingTable {
	return n.discoverer.Table()
}

// Run starts the node: bootstrap, heartbeat, and accept loop.
// It blocks until ctx is cancelled, then gracefully drains open connections.
func (n *Node) Run(ctx context.Context) error {
	n.logger.Printf("starting on %s", n.listener.Addr())

	// ── Bootstrap ─────────────────────────────────────────────────────────
	n.discoverer.Bootstrap(ctx, n.cfg.Seeds)

	// ── Heartbeat ─────────────────────────────────────────────────────────
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.discoverer.RunHeartbeat(ctx)
	}()

	// ── Accept loop ───────────────────────────────────────────────────────
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.acceptLoop(ctx)
	}()

	// Block until context done, then close listener to unblock Accept.
	<-ctx.Done()
	n.listener.Close()
	n.wg.Wait()

	n.stopped.Store(true)
	n.logger.Printf("stopped")
	return nil
}

// WaitStopped blocks until Run has returned and all goroutines have exited.
func (n *Node) WaitStopped() {
	n.wg.Wait()
}

// ── Accept loop ───────────────────────────────────────────────────────────────

// acceptLoop accepts TLS connections and spawns one goroutine per connection.
// The loop exits when the listener is closed (by Run's ctx-done path).
func (n *Node) acceptLoop(ctx context.Context) {
	for {
		conn, err := n.listener.Accept()
		if err != nil {
			// Distinguish clean shutdown from real errors.
			if n.isShutdown(err) {
				return
			}
			n.logger.Printf("accept error: %v", err)
			// Exponential back-off to avoid busy-loop on persistent errors.
			time.Sleep(50 * time.Millisecond)
			continue
		}

		// Each connection runs in its own goroutine (wiki §Node Architecture).
		n.wg.Add(1)
		go func(c net.Conn) {
			defer n.wg.Done()
			n.handleConn(ctx, c)
		}(conn)
	}
}

// isShutdown returns true if err indicates the listener was intentionally closed.
func (n *Node) isShutdown(err error) bool {
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return netErr.Err != nil && netErr.Err.Error() == "use of closed network connection"
	}
	return false
}

// ── Per-connection dispatcher ─────────────────────────────────────────────────

// handleConn is the per-connection goroutine.  It reads wire frames in a loop
// and dispatches them to the appropriate handler.
//
// The connection is closed when:
//   - ctx is done.
//   - The peer closes the connection (ErrShortRead).
//   - An unrecoverable protocol error occurs.
func (n *Node) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	peer := conn.RemoteAddr().String()
	n.logger.Printf("connection from %s", peer)
	n.discoverer.RegisterIncoming(conn)

	// Context cancellation → set a short deadline to unblock the blocked Read.
	stop := context.AfterFunc(ctx, func() {
		conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
	})
	defer stop()

	for {
		// Read the next message header (blocks until data or deadline).
		hdr, payload, err := ReadMsg(conn)
		if err != nil {
			if errors.Is(err, ErrShortRead) || isTimeout(err) {
				break // peer closed or ctx cancelled
			}
			n.logger.Printf("conn %s: read error: %v — closing", peer, err)
			break
		}

		// Dispatch by message type.
		if dispErr := n.dispatch(conn, hdr, payload); dispErr != nil {
			n.logger.Printf("conn %s: dispatch 0x%02x error: %v", peer, hdr.Type, dispErr)
			// Non-fatal: continue reading subsequent messages.
		}
	}

	n.logger.Printf("connection closed: %s", peer)
}

// dispatch routes a decoded message to the correct handler.
func (n *Node) dispatch(conn net.Conn, hdr Header, payload []byte) error {
	switch hdr.Type {
	case MsgPing:
		return HandlePing(conn)

	case MsgPong:
		return HandlePong(conn)

	case MsgStore:
		return n.transfer.HandleStore(conn, payload)

	case MsgGet:
		return n.transfer.HandleGet(conn, payload)

	case MsgAnnounce:
		return n.transfer.HandleAnnounce(conn, payload)

	default:
		return fmt.Errorf("unknown message type 0x%02x", hdr.Type)
	}
}

// isTimeout returns true for net.Error timeout errors (used to detect
// context-driven deadline expiry without importing context in the loop).
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// ── BlockStore adapter (so node.go compiles without importing ztss-storage) ──

// BlockStore is the storage interface consumed by this package.
// It mirrors storage.BlockStore exactly, avoiding an import cycle between
// ztss-node and ztss-storage.
//
// In production: pass a *storage.FileSystemStore or *storage.InMemoryStore.
// Both satisfy this interface without any adapter code.
type BlockStore interface {
	Put(cid [32]byte, data []byte) error
	Get(cid [32]byte) ([]byte, error)
	Has(cid [32]byte) bool
}
