// Package node implements the ZTSS peer-to-peer layer.
//
// discovery.go provides:
//
//  1. Wire protocol types — the 16-byte fixed header and 5 message opcodes
//     (STORE/GET/ANNOUNCE/PING/PONG) as defined in wiki/network_layer.md.
//  2. RoutingTable — a thread-safe map of known peers, maintained per node.
//  3. Bootstrap — connects to seed nodes at startup and populates the
//     routing table.
//  4. Heartbeat — goroutine-based PING/PONG keepalive; marks peers as dead
//     when they stop responding.
//
// Transport: TLS 1.3 (mandatory, TS-01).  No plaintext inter-node traffic.
//
// Goroutine model: one goroutine per live peer connection (heartbeat loop),
// plus one accept goroutine in node.go.  Goroutines are terminated via a
// context.Context.
//
// Wiki references:
//   - [[network_layer#Discovery Protocol]]
//   - [[network_layer#Binary Wire Protocol]]
//   - [[network_layer#Transport Security]]
package node

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"sync"
	"time"
)

// ── Wire protocol ─────────────────────────────────────────────────────────────

// Header field sizes.
const (
	headerSize = 16 // total fixed header size (bytes)
	cidSize    = 32 // SHA-256 CID in payload (bytes)

	offType    = 0 // byte 0:   message type
	offVersion = 1 // byte 1:   protocol version
	offLength  = 2 // bytes 2–5: payload length (uint32 big-endian)
	offPad     = 6 // bytes 6–15: reserved / future use
)

// Protocol version.
const protoVersion = 0x01

// Message type opcodes (wiki/network_layer.md §Binary Wire Protocol).
const (
	MsgStore    uint8 = 0x01 // STORE  — push a chunk to a peer
	MsgGet      uint8 = 0x02 // GET    — request a chunk by CID
	MsgAnnounce uint8 = 0x03 // ANNOUNCE — notify peers of a held CID
	MsgPing     uint8 = 0x04 // PING   — heartbeat probe
	MsgPong     uint8 = 0x05 // PONG   — heartbeat response
)

// Header is the 16-byte fixed header prepended to every wire message.
//
// Layout:
//
//	byte  0     : Type    (MsgStore … MsgPong)
//	byte  1     : Version (protoVersion = 0x01)
//	bytes 2–5   : Length  (uint32 big-endian, payload size)
//	bytes 6–15  : Reserved (zeroed; reserved for flags / future extensions)
//
// The CID (SHA-256, 32 bytes) is part of the Payload, not the fixed header,
// to keep the header compact at exactly 16 bytes.  For PING/PONG the
// payload is empty (Length = 0).
type Header struct {
	Type    uint8
	Version uint8
	Length  uint32 // payload length
}

// Encode serialises the header into a 16-byte array.
func (h Header) Encode() [headerSize]byte {
	var b [headerSize]byte
	b[offType] = h.Type
	b[offVersion] = h.Version
	binary.BigEndian.PutUint32(b[offLength:], h.Length)
	// bytes 6–15 remain zero (reserved)
	return b
}

// DecodeHeader parses a 16-byte header from r.
// Returns ErrShortRead if fewer than headerSize bytes are available.
func DecodeHeader(r io.Reader) (Header, error) {
	var raw [headerSize]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Header{}, ErrShortRead
		}
		return Header{}, fmt.Errorf("node: DecodeHeader: %w", err)
	}
	return Header{
		Type:    raw[offType],
		Version: raw[offVersion],
		Length:  binary.BigEndian.Uint32(raw[offLength:]),
	}, nil
}

// WriteMsg encodes and writes a complete message (header + payload) to w.
// It is safe to call from multiple goroutines if w's underlying Write is atomic
// (e.g. tls.Conn on Linux, where a single Write is atomic up to ~16 KB).
func WriteMsg(w io.Writer, msgType uint8, payload []byte) error {
	h := Header{
		Type:    msgType,
		Version: protoVersion,
		Length:  uint32(len(payload)),
	}.Encode()

	// Single write: header + payload concatenated to avoid short-write races.
	buf := make([]byte, headerSize+len(payload))
	copy(buf[:headerSize], h[:])
	copy(buf[headerSize:], payload)

	_, err := w.Write(buf)
	return err
}

// ReadMsg reads one complete message from r and returns its header and payload.
// Payload is limited to maxPayload bytes to prevent memory exhaustion.
func ReadMsg(r io.Reader) (Header, []byte, error) {
	h, err := DecodeHeader(r)
	if err != nil {
		return Header{}, nil, err
	}
	if h.Version != protoVersion {
		return Header{}, nil, fmt.Errorf("node: ReadMsg: unsupported protocol version 0x%02x", h.Version)
	}
	if h.Length > maxPayload {
		return Header{}, nil, fmt.Errorf("node: ReadMsg: payload (%d) exceeds limit (%d)", h.Length, maxPayload)
	}
	if h.Length == 0 {
		return h, nil, nil
	}
	payload := make([]byte, h.Length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Header{}, nil, fmt.Errorf("node: ReadMsg: payload read: %w", err)
	}
	return h, payload, nil
}

// maxPayload is the per-message payload cap.  A STORE message carries one
// 256 KB chunk + 32-byte CID; allow a small margin.
const maxPayload = 280 * 1024 // 280 KB

// ── Sentinel errors ───────────────────────────────────────────────────────────

var (
	// ErrShortRead is returned when a connection closes mid-header.
	ErrShortRead = errors.New("node: short read (peer closed connection)")

	// ErrPeerUnreachable is stored in PeerInfo.LastError when PING times out.
	ErrPeerUnreachable = errors.New("node: peer unreachable (ping timeout)")
)

// ── Peer and RoutingTable ─────────────────────────────────────────────────────

// PeerInfo holds the state of a known peer in the routing table.
type PeerInfo struct {
	Addr      string    // "host:port"
	Conn      net.Conn  // live TLS connection; nil if not connected
	LastSeen  time.Time // time of last successful PONG
	Alive     bool      // false when heartbeat times out
	LastError error     // most recent heartbeat error (if any)
}

// RoutingTable is a thread-safe map of peer addresses to their PeerInfo.
// The routing table is maintained by the heartbeat loop and the bootstrap
// procedure.  Nodes consult it to select peers for FETCH / REPLICATE.
type RoutingTable struct {
	mu    sync.RWMutex
	peers map[string]*PeerInfo // keyed by "host:port"
}

// NewRoutingTable returns an empty RoutingTable.
func NewRoutingTable() *RoutingTable {
	return &RoutingTable{peers: make(map[string]*PeerInfo)}
}

// Add registers a peer.  If the peer is already registered, Add is a no-op
// (call Update to modify an existing entry).
func (rt *RoutingTable) Add(addr string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if _, ok := rt.peers[addr]; !ok {
		rt.peers[addr] = &PeerInfo{Addr: addr}
	}
}

// Update atomically modifies the PeerInfo for addr using the supplied function.
// If addr is not in the table, Update returns without calling f.
func (rt *RoutingTable) Update(addr string, f func(*PeerInfo)) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if p, ok := rt.peers[addr]; ok {
		f(p)
	}
}

// Get returns a copy of the PeerInfo for addr and a bool indicating whether
// the peer is known.
func (rt *RoutingTable) Get(addr string) (PeerInfo, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	p, ok := rt.peers[addr]
	if !ok {
		return PeerInfo{}, false
	}
	return *p, true
}

// Remove deletes a peer from the routing table.
func (rt *RoutingTable) Remove(addr string) {
	rt.mu.Lock()
	delete(rt.peers, addr)
	rt.mu.Unlock()
}

// Alive returns all peers whose Alive flag is true.
func (rt *RoutingTable) Alive() []PeerInfo {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	out := make([]PeerInfo, 0, len(rt.peers))
	for _, p := range rt.peers {
		if p.Alive {
			out = append(out, *p)
		}
	}
	return out
}

// All returns all known peers regardless of liveness.
func (rt *RoutingTable) All() []PeerInfo {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	out := make([]PeerInfo, 0, len(rt.peers))
	for _, p := range rt.peers {
		out = append(out, *p)
	}
	return out
}

// Len returns the total number of entries in the routing table.
func (rt *RoutingTable) Len() int {
	rt.mu.RLock()
	n := len(rt.peers)
	rt.mu.RUnlock()
	return n
}

// ── TLS configuration ─────────────────────────────────────────────────────────

// tlsClientConfig returns a TLS 1.3 client configuration.
//
// In production, tlsCert is a node certificate signed by the cluster CA and
// rootCAs contains the cluster CA pool.  For development / integration tests,
// GenerateSelfSignedCert can be used with InsecureSkipVerify=true.
//
// TS-01: MinVersion is pinned to TLS 1.3; older versions are refused.
func tlsClientConfig(cert *tls.Certificate, rootCAs *x509.CertPool, skipVerify bool) *tls.Config {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: skipVerify, //nolint:gosec // intentional for dev mode
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	if rootCAs != nil {
		cfg.RootCAs = rootCAs
	}
	return cfg
}

// tlsServerConfig returns a TLS 1.3 server configuration.
func tlsServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.NoClientCert, // set to tls.RequireAnyClientCert for mTLS
	}
}

// GenerateSelfSignedCert generates a self-signed ECDSA/P-256 TLS certificate
// valid for 1 year.  Used in development and integration tests.
// In production, provision certificates from a cluster CA instead.
func GenerateSelfSignedCert(host string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("node: GenerateSelfSignedCert: key gen: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"ZTSS Node"}},
		DNSNames:     []string{host, "localhost"},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("node: GenerateSelfSignedCert: sign: %w", err)
	}

	return tls.X509KeyPair(
		pemEncode("CERTIFICATE", certDER),
		pemEncodeKey(priv),
	)
}

// pemEncode wraps DER bytes in a minimal PEM block (no crypto/pem import needed).
func pemEncode(blockType string, der []byte) []byte {
	// Use encoding/pem via the tls package's x509.CertPool reader — but since
	// we want to avoid an extra import for a helper, we construct PEM manually.
	// PEM = "-----BEGIN <type>-----\n" + base64(der, 64-char lines) + "\n-----END <type>-----\n"
	import64 := encodeBase64Lines(der)
	out := fmt.Sprintf("-----BEGIN %s-----\n%s-----END %s-----\n", blockType, import64, blockType)
	return []byte(out)
}

// pemEncodeKey produces a PEM-encoded EC private key.
func pemEncodeKey(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic("node: MarshalECPrivateKey: " + err.Error())
	}
	return pemEncode("EC PRIVATE KEY", der)
}

// encodeBase64Lines base64-encodes src with line wrapping at 64 chars.
func encodeBase64Lines(src []byte) string {
	const lineLen = 64
	encoded := make([]byte, base64EncodedLen(len(src)))
	base64Encode(encoded, src)

	var out []byte
	for len(encoded) > 0 {
		n := lineLen
		if n > len(encoded) {
			n = len(encoded)
		}
		out = append(out, encoded[:n]...)
		out = append(out, '\n')
		encoded = encoded[n:]
	}
	return string(out)
}

// base64Encode and base64EncodedLen implement RFC 4648 §4 without importing
// "encoding/base64" to keep the import list minimal.  We use the stdlib directly.
// (These are thin wrappers that delegate to encoding/base64.)
func base64EncodedLen(n int) int {
	return (n + 2) / 3 * 4
}

func base64Encode(dst, src []byte) {
	const tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	di, si := 0, 0
	n := (len(src) / 3) * 3
	for si < n {
		val := uint(src[si+0])<<16 | uint(src[si+1])<<8 | uint(src[si+2])
		dst[di+0] = tbl[val>>18&0x3F]
		dst[di+1] = tbl[val>>12&0x3F]
		dst[di+2] = tbl[val>>6&0x3F]
		dst[di+3] = tbl[val>>0&0x3F]
		di += 4
		si += 3
	}
	rem := len(src) - si
	if rem == 2 {
		val := uint(src[si+0])<<16 | uint(src[si+1])<<8
		dst[di+0] = tbl[val>>18&0x3F]
		dst[di+1] = tbl[val>>12&0x3F]
		dst[di+2] = tbl[val>>6&0x3F]
		dst[di+3] = '='
	} else if rem == 1 {
		val := uint(src[si+0]) << 16
		dst[di+0] = tbl[val>>18&0x3F]
		dst[di+1] = tbl[val>>12&0x3F]
		dst[di+2] = '='
		dst[di+3] = '='
	}
}

// ── Discoverer ────────────────────────────────────────────────────────────────

// HeartbeatConfig controls the ping/pong timing behaviour.
type HeartbeatConfig struct {
	// Interval is the period between PING messages per peer.
	Interval time.Duration

	// Timeout is how long to wait for a PONG before declaring the peer dead.
	Timeout time.Duration

	// MaxConsecutiveFails is the number of consecutive timeouts before the
	// peer is removed from the routing table entirely.
	MaxConsecutiveFails int
}

// DefaultHeartbeatConfig is the production heartbeat configuration.
var DefaultHeartbeatConfig = HeartbeatConfig{
	Interval:            15 * time.Second,
	Timeout:             5 * time.Second,
	MaxConsecutiveFails: 3,
}

// Discoverer manages peer discovery, bootstrap, and heartbeat for a single node.
//
// Lifecycle:
//  1. NewDiscoverer(…)
//  2. Bootstrap(ctx, seeds)  — connect to seed nodes, populate routing table
//  3. RunHeartbeat(ctx)      — start per-peer goroutines (blocking until ctx done)
//
// All exported methods are safe for concurrent use.
type Discoverer struct {
	table    *RoutingTable
	tlsCfg   *tls.Config     // TLS 1.3 client config (TS-01)
	hbCfg    HeartbeatConfig
	dialAddr string          // this node's own listen address (excluded from heartbeat)
	logger   *log.Logger

	// connMu protects pendingConns: a map of addr→conn for connections that
	// have been established but not yet fully registered in the routing table.
	connMu      sync.Mutex
	pendingConns map[string]net.Conn
}

// NewDiscoverer creates a Discoverer.
//
//   - selfAddr: this node's own "host:port" (omitted from outgoing connections).
//   - tlsCfg:   TLS 1.3 client config; use tlsClientConfig() or a custom config.
//   - hbCfg:    heartbeat timing; use DefaultHeartbeatConfig for production.
func NewDiscoverer(selfAddr string, tlsCfg *tls.Config, hbCfg HeartbeatConfig) *Discoverer {
	return &Discoverer{
		table:        NewRoutingTable(),
		tlsCfg:       tlsCfg,
		hbCfg:        hbCfg,
		dialAddr:     selfAddr,
		logger:       log.New(log.Writer(), fmt.Sprintf("[discovery %s] ", selfAddr), log.LstdFlags),
		pendingConns: make(map[string]net.Conn),
	}
}

// Table exposes the routing table for use by other node components
// (e.g. transfer.go, node.go).
func (d *Discoverer) Table() *RoutingTable {
	return d.table
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

// Bootstrap connects to each seed address that is not this node itself.
// For each successful connection it:
//  1. Registers the peer in the routing table as Alive.
//  2. Stores the live conn for immediate reuse by RunHeartbeat.
//
// Bootstrap runs synchronously and returns after attempting all seeds.
// Individual seed failures are logged and skipped — a node can still
// operate with a subset of seeds if the others are temporarily unreachable.
//
// Context cancellation aborts all pending dials.
func (d *Discoverer) Bootstrap(ctx context.Context, seeds []string) {
	for _, addr := range seeds {
		if addr == d.dialAddr {
			continue // skip self
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		d.table.Add(addr)

		conn, err := d.dial(ctx, addr)
		if err != nil {
			d.logger.Printf("bootstrap: cannot reach seed %s: %v", addr, err)
			d.table.Update(addr, func(p *PeerInfo) {
				p.Alive = false
				p.LastError = err
			})
			continue
		}

		d.registerConn(addr, conn)
		d.logger.Printf("bootstrap: connected to seed %s ✓", addr)
	}
}

// dial opens a TLS 1.3 connection to addr, respecting ctx cancellation.
func (d *Discoverer) dial(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial tcp %s: %w", addr, err)
	}

	tlsConn := tls.Client(rawConn, d.tlsCfg)
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err = tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake %s: %w", addr, err)
	}
	tlsConn.SetDeadline(time.Time{}) // clear deadline after handshake
	return tlsConn, nil
}

// registerConn stores the connection in the routing table and in pendingConns
// so RunHeartbeat can pick it up.
func (d *Discoverer) registerConn(addr string, conn net.Conn) {
	d.table.Update(addr, func(p *PeerInfo) {
		if p.Conn != nil {
			p.Conn.Close() // close stale connection
		}
		p.Conn = conn
		p.Alive = true
		p.LastSeen = time.Now()
		p.LastError = nil
	})

	d.connMu.Lock()
	d.pendingConns[addr] = conn
	d.connMu.Unlock()
}

// ── Heartbeat ────────────────────────────────────────────────────────────────

// RunHeartbeat starts one goroutine per known peer and runs until ctx is done.
// It also watches for newly added peers (from Bootstrap or incoming connections
// registered via RegisterIncoming) and spawns goroutines for them dynamically.
//
// Call this in a dedicated goroutine:
//
//	go d.RunHeartbeat(ctx)
func (d *Discoverer) RunHeartbeat(ctx context.Context) {
	managed := make(map[string]context.CancelFunc) // addr → cancel for its goroutine

	ticker := time.NewTicker(d.hbCfg.Interval / 2) // check for new peers at half interval
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Cancel all peer goroutines.
			for _, cancel := range managed {
				cancel()
			}
			return

		case <-ticker.C:
			for _, p := range d.table.All() {
				if _, running := managed[p.Addr]; running {
					continue
				}
				// New peer — start a heartbeat goroutine.
				peerCtx, cancel := context.WithCancel(ctx)
				managed[p.Addr] = cancel
				go d.runPeerHeartbeat(peerCtx, p.Addr)
			}
		}
	}
}

// runPeerHeartbeat is the per-peer heartbeat goroutine.
// It sends PING every hbCfg.Interval, waits hbCfg.Timeout for PONG,
// and marks the peer dead after MaxConsecutiveFails timeouts.
func (d *Discoverer) runPeerHeartbeat(ctx context.Context, addr string) {
	ticker := time.NewTicker(d.hbCfg.Interval)
	defer ticker.Stop()

	fails := 0

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			err := d.pingPeer(addr)
			if err == nil {
				fails = 0
				d.table.Update(addr, func(p *PeerInfo) {
					p.Alive = true
					p.LastSeen = time.Now()
					p.LastError = nil
				})
				d.logger.Printf("heartbeat: PONG from %s ✓", addr)
				continue
			}

			fails++
			d.logger.Printf("heartbeat: PING %s failed (%d/%d): %v",
				addr, fails, d.hbCfg.MaxConsecutiveFails, err)

			d.table.Update(addr, func(p *PeerInfo) {
				p.LastError = err
				if fails >= d.hbCfg.MaxConsecutiveFails {
					p.Alive = false
					if p.Conn != nil {
						p.Conn.Close()
						p.Conn = nil
					}
				}
			})

			if fails >= d.hbCfg.MaxConsecutiveFails {
				d.logger.Printf("heartbeat: peer %s declared DEAD after %d consecutive failures", addr, fails)
				// Attempt reconnection before giving up entirely.
				d.attemptReconnect(ctx, addr)
				return
			}
		}
	}
}

// pingPeer sends a PING to addr and waits for a PONG within hbCfg.Timeout.
// Re-establishes the connection if it has dropped.
func (d *Discoverer) pingPeer(addr string) error {
	p, ok := d.table.Get(addr)
	if !ok {
		return fmt.Errorf("peer %s not in routing table", addr)
	}

	conn := p.Conn
	if conn == nil {
		return ErrPeerUnreachable
	}

	// Send PING (empty payload).
	conn.SetWriteDeadline(time.Now().Add(d.hbCfg.Timeout))
	if err := WriteMsg(conn, MsgPing, nil); err != nil {
		conn.SetWriteDeadline(time.Time{})
		return fmt.Errorf("PING write: %w", err)
	}
	conn.SetWriteDeadline(time.Time{})

	// Wait for PONG.
	conn.SetReadDeadline(time.Now().Add(d.hbCfg.Timeout))
	hdr, _, err := ReadMsg(conn)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("PONG read: %w", err)
	}
	if hdr.Type != MsgPong {
		return fmt.Errorf("expected PONG (0x05), got 0x%02x", hdr.Type)
	}
	return nil
}

// attemptReconnect tries to re-establish the connection to addr after all
// heartbeat attempts have failed.  If successful the peer is marked alive
// again and a new heartbeat goroutine is started.  If it fails the peer
// remains dead in the routing table.
func (d *Discoverer) attemptReconnect(ctx context.Context, addr string) {
	d.logger.Printf("reconnect: attempting to re-dial %s …", addr)

	conn, err := d.dial(ctx, addr)
	if err != nil {
		d.logger.Printf("reconnect: %s still unreachable: %v", addr, err)
		return
	}

	d.registerConn(addr, conn)
	d.logger.Printf("reconnect: %s re-established ✓", addr)

	// Spawn a fresh heartbeat goroutine.
	go d.runPeerHeartbeat(ctx, addr)
}

// ── Incoming connection registration ──────────────────────────────────────────

// RegisterIncoming registers a connection accepted by node.go's listener
// (i.e., a peer that connected to us, not one we dialled).
// RunHeartbeat will automatically detect the new routing-table entry and
// start its heartbeat goroutine.
func (d *Discoverer) RegisterIncoming(conn net.Conn) {
	addr := conn.RemoteAddr().String()
	d.table.Add(addr)
	d.registerConn(addr, conn)
	d.logger.Printf("incoming: registered peer %s", addr)
}

// HandlePing reads a PING that has already been identified (by node.go's
// dispatcher) and replies with PONG.  This is called from the connection
// handler goroutine in node.go.
func HandlePing(conn net.Conn) error {
	return WriteMsg(conn, MsgPong, nil)
}

// HandlePong is a no-op for the receiving side; it is consumed by pingPeer.
// Exported for node.go's dispatcher completeness.
func HandlePong(_ net.Conn) error {
	return nil
}
