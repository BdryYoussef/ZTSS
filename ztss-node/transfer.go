// transfer.go — STORE, GET, and ANNOUNCE message handlers for ZTSS nodes.
//
// This file implements:
//
//  1. TransferLayer — server-side handlers invoked by node.go's dispatcher.
//     Each handler: decodes the payload, enforces security constraints (CID
//     integrity, storage-only-ciphertext, capacity limits), and responds.
//
//  2. Client helpers — SendStore / SendGet / SendAnnounce for initiating
//     outgoing chunk transfers to peer nodes over existing TLS connections.
//
//  3. CIDIndex — a thread-safe map of CID → []addr, telling each node which
//     peers have announced ownership of a given chunk.  Used by the routing
//     layer (ReplicationManager) to direct FETCH requests.
//
// Wire payload formats (all multi-byte integers are big-endian):
//
//	STORE  payload: [ CID:32B ][ Data:NB ]   (N = hdr.Length - 32)
//	GET    payload: [ CID:32B ]              (hdr.Length = 32)
//	ANNOUNCE payload: [ CID:32B ]            (hdr.Length = 32)
//
//	GET response (sent back on same conn): STORE message with the chunk.
//	If the CID is not found, a single-byte "not-found" response is sent
//	using MsgType 0x00 (ErrMsg).
//
// Security constraints:
//   ES2: Nodes never inspect chunk semantics.  The CID is verified as
//        SHA-256(payload data), but the data is assumed to be ciphertext.
//   ES3: All traffic flows over the TLS conn established by node.go —
//        this file never opens raw TCP connections.
//   TS-02: Every STORE handler recomputes SHA-256(data) and compares
//          against the CID in the header; mismatches are rejected.
//
// Wiki references:
//   - [[network_layer#Binary Wire Protocol]]
//   - [[storage_layer#BlockStore Interface]]
//   - [[security_rules#ES2]]
//   - [[security_rules#TS-02]]
package node

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"
)

// ── Wire payload constants ────────────────────────────────────────────────────

const (
	// MsgErr is a single-byte response type used for error replies on GET.
	// Not part of the 5 CDC opcodes; used internally for negative responses.
	MsgErr uint8 = 0x00
)

// ── CIDIndex ──────────────────────────────────────────────────────────────────

// CIDIndex is a thread-safe reverse map from a 32-byte CID to the set of
// peer addresses that have announced ownership of that chunk.
//
// Used by the routing layer to direct FETCH requests to a specific peer
// without a full broadcast.  Updated by HandleAnnounce on the server side
// and by SendAnnounce on the client side.
type CIDIndex struct {
	mu  sync.RWMutex
	idx map[[32]byte]map[string]struct{} // cid → set of peer addrs
}

// NewCIDIndex returns an empty CIDIndex.
func NewCIDIndex() *CIDIndex {
	return &CIDIndex{idx: make(map[[32]byte]map[string]struct{})}
}

// Add records that peer addr holds the chunk identified by cid.
func (c *CIDIndex) Add(cid [32]byte, addr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.idx[cid] == nil {
		c.idx[cid] = make(map[string]struct{})
	}
	c.idx[cid][addr] = struct{}{}
}

// Holders returns the addresses of all peers known to hold cid.
// Returns nil if no peer has announced the CID.
func (c *CIDIndex) Holders(cid [32]byte) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	peers := c.idx[cid]
	if len(peers) == 0 {
		return nil
	}
	out := make([]string, 0, len(peers))
	for addr := range peers {
		out = append(out, addr)
	}
	return out
}

// Remove removes addr from the holder set of cid (e.g., when a node goes dead).
func (c *CIDIndex) Remove(cid [32]byte, addr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.idx[cid] != nil {
		delete(c.idx[cid], addr)
	}
}

// ── TransferLayer ─────────────────────────────────────────────────────────────

// TransferLayer wraps a BlockStore and exposes the three server-side message
// handlers (HandleStore / HandleGet / HandleAnnounce) that node.go dispatches to.
type TransferLayer struct {
	store    BlockStore
	table    *RoutingTable
	cidIdx   *CIDIndex
	capacity int64 // maximum bytes the store may hold (0 = unlimited)
	used     int64 // approximate current usage (not persisted across restarts)
	usedMu   sync.Mutex
}

// NewTransferLayer constructs a TransferLayer.
//
//   - store:    chunk storage backend (InMemoryStore or FileSystemStore).
//   - table:    routing table from the Discoverer (used by HandleAnnounce to
//     look up the announcing peer's address).
//   - capacity: maximum storage in bytes; 0 disables the limit.
func NewTransferLayer(store BlockStore, table *RoutingTable, capacity int64) *TransferLayer {
	return &TransferLayer{
		store:    store,
		table:    table,
		cidIdx:   NewCIDIndex(),
		capacity: capacity,
	}
}

// CIDIndex exposes the index to external consumers (e.g. the ReplicationManager).
func (tl *TransferLayer) CIDIndex() *CIDIndex {
	return tl.cidIdx
}

// ── STORE handler ─────────────────────────────────────────────────────────────

// HandleStore processes an incoming STORE message.
//
// Payload format: [ CID:32B ][ Data:(hdr.Length-32)B ]
//
// Steps:
//  1. Validate payload length (≥ 33 bytes: 32 CID + ≥ 1 data).
//  2. Extract CID and chunk data.
//  3. Recompute SHA-256(data) and compare against CID (TS-02).
//  4. Check storage capacity (reject if full).
//  5. Call BlockStore.Put(cid, data).
//
// No response is sent on success (fire-and-forget STORE semantics).
// On error, a MsgErr frame is written back so the sender can detect failure.
func (tl *TransferLayer) HandleStore(conn net.Conn, payload []byte) error {
	cid, data, err := decodeChunkPayload(payload)
	if err != nil {
		writeErrMsg(conn, err)
		return fmt.Errorf("HandleStore: decode: %w", err)
	}

	// TS-02: verify CID = SHA-256(data) before storing.
	computed := sha256.Sum256(data)
	if computed != cid {
		writeErrMsg(conn, ErrCIDMismatch)
		return fmt.Errorf("HandleStore: %w (peer=%s)", ErrCIDMismatch, conn.RemoteAddr())
	}

	// Capacity check (ES2: we only count bytes, never inspect content).
	if err = tl.reserveCapacity(int64(len(data))); err != nil {
		writeErrMsg(conn, err)
		return fmt.Errorf("HandleStore: %w", err)
	}

	if err = tl.store.Put(cid, data); err != nil {
		tl.releaseCapacity(int64(len(data)))
		writeErrMsg(conn, err)
		return fmt.Errorf("HandleStore: Put: %w", err)
	}

	return nil // success; no ACK frame (fire-and-forget)
}

// ── GET handler ───────────────────────────────────────────────────────────────

// HandleGet processes an incoming GET message and sends the chunk back.
//
// Request payload format: [ CID:32B ]
//
// Response:
//   - On success: a STORE message with the chunk [CID:32B][Data].
//   - On not-found: a MsgErr frame with a 1-byte payload (0x01 = not found).
//
// The response is sent on the same conn (request/response over one connection).
func (tl *TransferLayer) HandleGet(conn net.Conn, payload []byte) error {
	cid, err := decodeCID(payload)
	if err != nil {
		writeErrMsg(conn, err)
		return fmt.Errorf("HandleGet: decode: %w", err)
	}

	data, err := tl.store.Get(cid)
	if err != nil {
		if errors.Is(err, errNotFound(cid)) || isNotFound(err) {
			writeErrMsg(conn, ErrChunkNotFound)
			return nil // not-found is a normal condition, not a protocol error
		}
		writeErrMsg(conn, err)
		return fmt.Errorf("HandleGet: Get: %w", err)
	}

	// Respond with a STORE message carrying the chunk.
	resp := buildChunkPayload(cid, data)
	if err = WriteMsg(conn, MsgStore, resp); err != nil {
		return fmt.Errorf("HandleGet: write response: %w", err)
	}
	return nil
}

// ── ANNOUNCE handler ──────────────────────────────────────────────────────────

// HandleAnnounce processes an incoming ANNOUNCE message.
//
// Payload format: [ CID:32B ]
//
// Records in the CIDIndex that the announcing peer (identified by
// conn.RemoteAddr()) holds the chunk identified by the CID.  No response
// is sent (announcement is fire-and-forget).
func (tl *TransferLayer) HandleAnnounce(conn net.Conn, payload []byte) error {
	cid, err := decodeCID(payload)
	if err != nil {
		return fmt.Errorf("HandleAnnounce: decode: %w", err)
	}

	peerAddr := conn.RemoteAddr().String()
	tl.cidIdx.Add(cid, peerAddr)
	return nil
}

// ── Client-side helpers ───────────────────────────────────────────────────────

// SendStore sends a STORE message to conn, delivering the chunk (cid, data).
// The payload is [ CID:32B ][ Data:NB ].
//
// Called by the ReplicationManager to push chunks to peer nodes.
func SendStore(conn net.Conn, cid [32]byte, data []byte) error {
	payload := buildChunkPayload(cid, data)
	if err := WriteMsg(conn, MsgStore, payload); err != nil {
		return fmt.Errorf("SendStore: write: %w", err)
	}
	return nil
}

// SendGet sends a GET request to conn for the chunk identified by cid,
// then reads and returns the response data.
//
// On success: returns the chunk bytes.
// On not-found (peer returns MsgErr): returns ErrChunkNotFound.
// On any other error: returns the wrapped error.
func SendGet(conn net.Conn, cid [32]byte) ([]byte, error) {
	// Send request.
	if err := WriteMsg(conn, MsgGet, cid[:]); err != nil {
		return nil, fmt.Errorf("SendGet: write request: %w", err)
	}

	// Read response.
	hdr, payload, err := ReadMsg(conn)
	if err != nil {
		return nil, fmt.Errorf("SendGet: read response: %w", err)
	}

	switch hdr.Type {
	case MsgErr:
		return nil, ErrChunkNotFound

	case MsgStore:
		// Decode the STORE response and verify CID integrity (TS-02).
		respCID, data, err := decodeChunkPayload(payload)
		if err != nil {
			return nil, fmt.Errorf("SendGet: decode response: %w", err)
		}
		if respCID != cid {
			return nil, fmt.Errorf("SendGet: CID in response (%x) ≠ requested (%x)", respCID, cid)
		}
		computed := sha256.Sum256(data)
		if computed != cid {
			return nil, fmt.Errorf("%w: peer returned corrupt data", ErrCIDMismatch)
		}
		return data, nil

	default:
		return nil, fmt.Errorf("SendGet: unexpected response type 0x%02x", hdr.Type)
	}
}

// SendAnnounce sends an ANNOUNCE message to conn indicating that this node
// holds the chunk identified by cid.
//
// The peer's HandleAnnounce records (cid → this node's addr) in its CIDIndex.
func SendAnnounce(conn net.Conn, cid [32]byte) error {
	if err := WriteMsg(conn, MsgAnnounce, cid[:]); err != nil {
		return fmt.Errorf("SendAnnounce: write: %w", err)
	}
	return nil
}

// AnnounceToAll sends an ANNOUNCE for cid to every live peer in table.
// Individual errors are logged; the function returns the number of successful
// announcements.
func AnnounceToAll(table *RoutingTable, cid [32]byte) int {
	peers := table.Alive()
	ok := 0
	for _, p := range peers {
		if p.Conn == nil {
			continue
		}
		if err := SendAnnounce(p.Conn, cid); err == nil {
			ok++
		}
	}
	return ok
}

// ── Payload codec helpers ─────────────────────────────────────────────────────

// buildChunkPayload constructs a STORE/GET-response payload: [CID:32][Data].
func buildChunkPayload(cid [32]byte, data []byte) []byte {
	out := make([]byte, 32+len(data))
	copy(out[:32], cid[:])
	copy(out[32:], data)
	return out
}

// decodeChunkPayload splits a STORE payload into CID and data.
// Requires len(payload) ≥ 33 (32-byte CID + ≥ 1 byte of data).
func decodeChunkPayload(payload []byte) ([32]byte, []byte, error) {
	if len(payload) < 33 {
		return [32]byte{}, nil, fmt.Errorf(
			"%w: STORE payload too short (%d bytes, need ≥ 33)", ErrMalformedPayload, len(payload),
		)
	}
	var cid [32]byte
	copy(cid[:], payload[:32])
	data := make([]byte, len(payload)-32)
	copy(data, payload[32:])
	return cid, data, nil
}

// decodeCID extracts a 32-byte CID from a GET or ANNOUNCE payload.
// Requires len(payload) == 32.
func decodeCID(payload []byte) ([32]byte, error) {
	if len(payload) != 32 {
		return [32]byte{}, fmt.Errorf(
			"%w: expected 32-byte CID, got %d bytes", ErrMalformedPayload, len(payload),
		)
	}
	var cid [32]byte
	copy(cid[:], payload)
	return cid, nil
}

// writeErrMsg sends a MsgErr frame with the error text as payload.
// Errors during write are silently discarded (best-effort).
func writeErrMsg(conn net.Conn, err error) {
	msg := []byte(err.Error())
	if len(msg) > 200 {
		msg = msg[:200]
	}
	WriteMsg(conn, MsgErr, msg) //nolint:errcheck // best-effort error notification
}

// ── Capacity tracking ─────────────────────────────────────────────────────────

// reserveCapacity tentatively reserves n bytes.  Returns ErrStorageFull if
// the capacity limit would be exceeded.  If capacity is 0 (unlimited), always
// returns nil.
func (tl *TransferLayer) reserveCapacity(n int64) error {
	if tl.capacity == 0 {
		return nil
	}
	tl.usedMu.Lock()
	defer tl.usedMu.Unlock()
	if tl.used+n > tl.capacity {
		return ErrStorageFull
	}
	tl.used += n
	return nil
}

// releaseCapacity reverses a prior reserveCapacity call on failure.
func (tl *TransferLayer) releaseCapacity(n int64) {
	if tl.capacity == 0 {
		return
	}
	tl.usedMu.Lock()
	tl.used -= n
	tl.usedMu.Unlock()
}

// ── Sentinel errors ───────────────────────────────────────────────────────────

var (
	// ErrCIDMismatch is returned when SHA-256(received data) ≠ the CID in the
	// STORE payload.  This detects a corrupt or malicious peer (TS-02).
	ErrCIDMismatch = errors.New("node: CID mismatch — SHA-256(data) does not match header CID")

	// ErrChunkNotFound is returned by SendGet when the peer does not hold the
	// requested CID.
	ErrChunkNotFound = errors.New("node: chunk not found on peer")

	// ErrMalformedPayload is returned when a payload fails length validation.
	ErrMalformedPayload = errors.New("node: malformed payload")

	// ErrStorageFull is returned by HandleStore when the node's capacity would
	// be exceeded.
	ErrStorageFull = errors.New("node: storage capacity exceeded")
)

// errNotFound constructs an error comparable with errors.Is for BlockStore
// not-found errors.  This is a shim because the node package does not import
// ztss-storage to avoid an import cycle; it checks the error message instead.
func errNotFound(_ [32]byte) error {
	return ErrChunkNotFound
}

// isNotFound returns true if err wraps or matches any "not found" error from
// the storage layer (detected by message prefix, avoiding direct import).
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return len(msg) >= 22 && msg[:22] == "ztss/storage: CID not "
}
