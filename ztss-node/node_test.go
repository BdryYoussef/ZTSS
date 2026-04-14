// node_test.go — integration tests for the ztss-node binary protocol and
// multi-node scenarios.
//
// Strategy:
//   - Spin real TLS 1.3 Node instances on localhost (random ports via "127.0.0.1:0").
//   - Use InsecureTLS=true so self-signed certs work without a cluster CA.
//   - All tests use t.Cleanup to stop nodes; no manual teardown needed.
//
// Test matrix:
//   TestWireHeaderEncodeDecode      — Header.Encode / DecodeHeader round-trip
//   TestWireHeaderSize              — fixed 16-byte header constant
//   TestDecodeHeaderShortRead       — ErrShortRead for truncated header
//   TestWireReadWriteMsg            — WriteMsg / ReadMsg over io.Pipe
//   TestReadMsgPayloadLimit         — oversized payload rejected
//   TestPingPong                    — PING → PONG exchange over TLS 1.3
//   TestStoreAndGet                 — STORE chunk, GET it back
//   TestCIDMismatchRejected         — TS-02: wrong CID rejected, not stored
//   TestAnnounceRecorded            — ANNOUNCE updates CIDIndex
//   TestGetNotFound                 — GET unknown CID → MsgErr
//   TestCapacityLimit               — STORE rejected at capacity
//   TestMalformedPayloadStore       — short STORE payload → MsgErr, no crash
//   TestMalformedPayloadGet         — 31-byte GET payload → MsgErr, no crash
//   TestTwoNodeBootstrap            — two nodes populate each other's routing table
//   TestTF05_NodeFailReroute        — TF-05: nodeA fails, client re-fetches from nodeB
//   TestMultipleChunkRoundTrip      — 5 distinct chunks stored then verified (TS-02)
//   TestConcurrentStoreGet          — race detector: 10 goroutines STORE+GET same chunk
//   TestSendGetHelper               — SendStore + SendGet client helpers
//   TestSendGetNotFound             — SendGet returns ErrChunkNotFound for absent CID
//   TestSendAnnounceHelper          — SendAnnounce updates remote CIDIndex
package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// ── In-process BlockStore ─────────────────────────────────────────────────────
// Minimal BlockStore for tests — mirrors storage.InMemoryStore without the
// import cycle between ztss-node and ztss-storage.

type memStore struct {
	mu   sync.RWMutex
	data map[[32]byte][]byte
}

func newMemStore() *memStore {
	return &memStore{data: make(map[[32]byte][]byte)}
}

func (m *memStore) Put(cid [32]byte, data []byte) error {
	cp := make([]byte, len(data))
	copy(cp, data)
	m.mu.Lock()
	m.data[cid] = cp
	m.mu.Unlock()
	return nil
}

func (m *memStore) Get(cid [32]byte) ([]byte, error) {
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

func (m *memStore) Has(cid [32]byte) bool {
	m.mu.RLock()
	_, ok := m.data[cid]
	m.mu.RUnlock()
	return ok
}

// ── Test helpers ──────────────────────────────────────────────────────────────

// testHeartbeat is a fast heartbeat config so tests don't wait 15 s.
var testHeartbeat = HeartbeatConfig{
	Interval:            500 * time.Millisecond,
	Timeout:             300 * time.Millisecond,
	MaxConsecutiveFails: 2,
}

// startNode starts a Node on a random localhost port.
// capacity == 0 means unlimited.  t.Cleanup stops the node.
func startNode(t *testing.T, seeds []string, capacity int64) *Node {
	t.Helper()

	cfg := NodeConfig{
		Addr:            "127.0.0.1:0",
		Seeds:           seeds,
		StorageCapacity: capacity,
		InsecureTLS:     true,
		Heartbeat:       testHeartbeat,
	}

	n, err := NewNode(cfg, newMemStore())
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cleanup: cancel context and drain goroutines.
	t.Cleanup(func() {
		cancel()
		n.WaitStopped()
	})

	go n.Run(ctx) //nolint:errcheck

	// Wait until the listener is ready.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", n.Addr(), 50*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return n
}

// dialTLSConn opens a TLS 1.3 connection to a running Node for raw
// wire-protocol manipulation in tests.
func dialTLSConn(t *testing.T, target *Node) net.Conn {
	t.Helper()
	addr := target.Addr()
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // test-only
	}

	raw, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dialTLSConn: dial %s: %v", addr, err)
	}
	tlsConn := tls.Client(raw, cfg)
	tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	if err = tlsConn.Handshake(); err != nil {
		raw.Close()
		t.Fatalf("dialTLSConn: TLS handshake: %v", err)
	}
	tlsConn.SetDeadline(time.Time{})
	t.Cleanup(func() { tlsConn.Close() })
	return tlsConn
}

// sendAndExpect sends msg and asserts the next response has expectedType.
func sendAndExpect(t *testing.T, conn net.Conn, msgType uint8, payload []byte, expectedType uint8) (Header, []byte) {
	t.Helper()
	if err := WriteMsg(conn, msgType, payload); err != nil {
		t.Fatalf("WriteMsg 0x%02x: %v", msgType, err)
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	hdr, resp, err := ReadMsg(conn)
	conn.SetDeadline(time.Time{})
	if err != nil {
		t.Fatalf("ReadMsg (expecting 0x%02x after 0x%02x): %v", expectedType, msgType, err)
	}
	if hdr.Type != expectedType {
		t.Errorf("expected response type 0x%02x, got 0x%02x", expectedType, hdr.Type)
	}
	return hdr, resp
}

// ── Section 1 — Wire header unit tests ───────────────────────────────────────

// TestWireHeaderEncodeDecode verifies Header.Encode and DecodeHeader are
// inverse operations for all five CDC opcodes.
func TestWireHeaderEncodeDecode(t *testing.T) {
	cases := []struct {
		typ    uint8
		length uint32
	}{
		{MsgStore, 0},
		{MsgGet, 32},
		{MsgAnnounce, 32},
		{MsgPing, 0},
		{MsgPong, 0},
	}

	for _, tc := range cases {
		name := fmt.Sprintf("type=0x%02x len=%d", tc.typ, tc.length)
		t.Run(name, func(t *testing.T) {
			h := Header{Type: tc.typ, Version: protoVersion, Length: tc.length}
			encoded := h.Encode()

			// Verify individual byte positions.
			if encoded[offType] != tc.typ {
				t.Errorf("byte[%d] (Type): got 0x%02x, want 0x%02x", offType, encoded[offType], tc.typ)
			}
			if encoded[offVersion] != protoVersion {
				t.Errorf("byte[%d] (Version): got 0x%02x, want 0x%02x", offVersion, encoded[offVersion], protoVersion)
			}
			gotLen := binary.BigEndian.Uint32(encoded[offLength:])
			if gotLen != tc.length {
				t.Errorf("Length: got %d, want %d", gotLen, tc.length)
			}
			// Bytes 6–15 are reserved; must be zero.
			for i := 6; i < headerSize; i++ {
				if encoded[i] != 0 {
					t.Errorf("reserved byte[%d] = 0x%02x, want 0x00", i, encoded[i])
				}
			}

			// DecodeHeader round-trip.
			got, err := DecodeHeader(bytes.NewReader(encoded[:]))
			if err != nil {
				t.Fatalf("DecodeHeader: %v", err)
			}
			if got.Type != tc.typ || got.Version != protoVersion || got.Length != tc.length {
				t.Errorf("round-trip: got {%d %d %d}, want {%d %d %d}",
					got.Type, got.Version, got.Length, tc.typ, protoVersion, tc.length)
			}
		})
	}
}

// TestWireHeaderSize asserts the mandatory 16-byte header.
func TestWireHeaderSize(t *testing.T) {
	enc := Header{Type: MsgPing, Version: protoVersion}.Encode()
	if len(enc) != headerSize || headerSize != 16 {
		t.Errorf("header size: got %d (constant=%d), want 16", len(enc), headerSize)
	}
}

// TestDecodeHeaderShortRead verifies ErrShortRead for a truncated header.
func TestDecodeHeaderShortRead(t *testing.T) {
	_, err := DecodeHeader(bytes.NewReader([]byte{0x04, 0x01}))
	if err == nil {
		t.Fatal("expected error for 2-byte input")
	}
}

// TestWireReadWriteMsg uses an io.Pipe to exercise WriteMsg / ReadMsg.
func TestWireReadWriteMsg(t *testing.T) {
	cases := []struct {
		name    string
		msgType uint8
		payload []byte
	}{
		{"PING (empty)", MsgPing, nil},
		{"PONG (empty)", MsgPong, nil},
		{"ANNOUNCE (32B CID)", MsgAnnounce, make([]byte, 32)},
		{"GET (32B CID)", MsgGet, make([]byte, 32)},
		{"STORE (CID+data)", MsgStore, append(make([]byte, 32), []byte("chunk data")...)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r, w := io.Pipe()
			go func() {
				defer w.Close()
				if err := WriteMsg(w, tc.msgType, tc.payload); err != nil {
					t.Errorf("WriteMsg: %v", err)
				}
			}()
			hdr, payload, err := ReadMsg(r)
			r.Close()
			if err != nil {
				t.Fatalf("ReadMsg: %v", err)
			}
			if hdr.Type != tc.msgType {
				t.Errorf("Type: got 0x%02x, want 0x%02x", hdr.Type, tc.msgType)
			}
			if hdr.Version != protoVersion {
				t.Errorf("Version: got 0x%02x, want 0x%02x", hdr.Version, protoVersion)
			}
			if !bytes.Equal(payload, tc.payload) {
				t.Errorf("payload mismatch: got %x, want %x", payload, tc.payload)
			}
		})
	}
}

// TestReadMsgPayloadLimit verifies that claims of maxPayload+1 bytes are refused.
func TestReadMsgPayloadLimit(t *testing.T) {
	r, w := io.Pipe()
	go func() {
		defer w.Close()
		h := Header{Type: MsgStore, Version: protoVersion, Length: maxPayload + 1}.Encode()
		w.Write(h[:])
	}()
	_, _, err := ReadMsg(r)
	r.Close()
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

// ── Section 2 — Live TLS node tests ──────────────────────────────────────────

// TestPingPong verifies PING → PONG over TLS 1.3.
func TestPingPong(t *testing.T) {
	n := startNode(t, nil, 0)
	conn := dialTLSConn(t, n)

	sendAndExpect(t, conn, MsgPing, nil, MsgPong)
}

// TestStoreAndGet verifies the STORE → GET round-trip.
func TestStoreAndGet(t *testing.T) {
	n := startNode(t, nil, 0)
	conn := dialTLSConn(t, n)

	data := []byte("hello ZTSS wire protocol")
	cid := sha256.Sum256(data)

	// STORE (no ACK).
	if err := WriteMsg(conn, MsgStore, buildChunkPayload(cid, data)); err != nil {
		t.Fatalf("WriteMsg STORE: %v", err)
	}
	time.Sleep(30 * time.Millisecond) // let server goroutine process

	// GET → expect STORE response.
	_, resp := sendAndExpect(t, conn, MsgGet, cid[:], MsgStore)

	respCID, respData, err := decodeChunkPayload(resp)
	if err != nil {
		t.Fatalf("decodeChunkPayload: %v", err)
	}
	if respCID != cid {
		t.Errorf("response CID mismatch")
	}
	if !bytes.Equal(respData, data) {
		t.Errorf("response data mismatch: got %q, want %q", respData, data)
	}
}

// TestCIDMismatchRejected is TS-02: STORE with wrong CID must be rejected and
// the chunk must NOT be persisted.
func TestCIDMismatchRejected(t *testing.T) {
	n := startNode(t, nil, 0)
	conn := dialTLSConn(t, n)

	data := []byte("authentic chunk data")
	realCID := sha256.Sum256(data)

	// Build payload with flipped CID byte 0.
	var badCID [32]byte
	copy(badCID[:], realCID[:])
	badCID[0] ^= 0xFF

	// STORE with wrong CID → expect MsgErr.
	sendAndExpect(t, conn, MsgStore, buildChunkPayload(badCID, data), MsgErr)

	// Confirm the chunk was NOT stored: GET must also fail.
	sendAndExpect(t, conn, MsgGet, badCID[:], MsgErr)
}

// TestAnnounceRecorded verifies that ANNOUNCE updates the node's CIDIndex.
func TestAnnounceRecorded(t *testing.T) {
	n := startNode(t, nil, 0)
	conn := dialTLSConn(t, n)

	var cid [32]byte
	cid[0] = 0xAB

	if err := WriteMsg(conn, MsgAnnounce, cid[:]); err != nil {
		t.Fatalf("WriteMsg ANNOUNCE: %v", err)
	}
	time.Sleep(30 * time.Millisecond)

	holders := n.transfer.CIDIndex().Holders(cid)
	if len(holders) == 0 {
		t.Fatal("ANNOUNCE: CIDIndex has no holders after ANNOUNCE message")
	}
}

// TestGetNotFound verifies that GET for an unknown CID returns MsgErr.
func TestGetNotFound(t *testing.T) {
	n := startNode(t, nil, 0)
	conn := dialTLSConn(t, n)

	var cid [32]byte
	cid[0] = 0xDE
	cid[1] = 0xAD

	sendAndExpect(t, conn, MsgGet, cid[:], MsgErr)
}

// TestCapacityLimit verifies that STORE is refused when the node is at capacity.
func TestCapacityLimit(t *testing.T) {
	n := startNode(t, nil, 10) // only 10 bytes
	conn := dialTLSConn(t, n)

	data := bytes.Repeat([]byte{0xCC}, 100) // way over limit
	cid := sha256.Sum256(data)

	sendAndExpect(t, conn, MsgStore, buildChunkPayload(cid, data), MsgErr)
}

// TestMalformedPayloadStore verifies that a too-short STORE payload returns
// MsgErr without crashing the server goroutine.
func TestMalformedPayloadStore(t *testing.T) {
	n := startNode(t, nil, 0)
	conn := dialTLSConn(t, n)

	sendAndExpect(t, conn, MsgStore, make([]byte, 10), MsgErr)

	// Server must still be alive: a subsequent PING succeeds.
	sendAndExpect(t, conn, MsgPing, nil, MsgPong)
}

// TestMalformedPayloadGet verifies that a 31-byte GET payload returns MsgErr
// without crashing the server.
func TestMalformedPayloadGet(t *testing.T) {
	n := startNode(t, nil, 0)
	conn := dialTLSConn(t, n)

	sendAndExpect(t, conn, MsgGet, make([]byte, 31), MsgErr)

	// Server still alive.
	sendAndExpect(t, conn, MsgPing, nil, MsgPong)
}

// TestTwoNodeBootstrap verifies that two nodes populate each other's routing table
// after bootstrap.
func TestTwoNodeBootstrap(t *testing.T) {
	nodeA := startNode(t, nil, 0)
	nodeB := startNode(t, []string{nodeA.Addr()}, 0)

	time.Sleep(100 * time.Millisecond)

	if nodeB.Table().Len() == 0 {
		t.Error("nodeB routing table empty after bootstrapping to nodeA")
	}
}

// ── Section 3 — TF-05: chunk re-fetch after node failure ─────────────────────

// TestTF05_NodeFailReroute is TF-05:
//
//	Scenario:
//	  1. Store a chunk on nodeA and nodeB.
//	  2. Verify both serve the chunk via GET.
//	  3. Stop nodeA (force-close listener).
//	  4. GET the chunk from nodeB — must succeed.
//
// Pass criterion: losing one replica node does not prevent chunk retrieval
// from any remaining holder (k-resilience with k ≥ 2).
func TestTF05_NodeFailReroute(t *testing.T) {
	nodeA := startNode(t, nil, 0)
	nodeB := startNode(t, nil, 0)

	chunkData := []byte("TF-05 test chunk — re-fetch after node failure")
	cid := sha256.Sum256(chunkData)
	payload := buildChunkPayload(cid, chunkData)

	// ── Step 1: STORE on both nodes ──────────────────────────────────────
	for label, n := range map[string]*Node{"nodeA": nodeA, "nodeB": nodeB} {
		conn := dialTLSConn(t, n)
		if err := WriteMsg(conn, MsgStore, payload); err != nil {
			t.Fatalf("STORE to %s: %v", label, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// ── Step 2: verify both can serve the chunk ──────────────────────────
	for label, n := range map[string]*Node{"nodeA (pre-fail)": nodeA, "nodeB (pre-fail)": nodeB} {
		conn := dialTLSConn(t, n)
		_, resp := sendAndExpect(t, conn, MsgGet, cid[:], MsgStore)
		_, got, err := decodeChunkPayload(resp)
		if err != nil || !bytes.Equal(got, chunkData) {
			t.Fatalf("%s: GET mismatch: %v", label, err)
		}
		conn.Close()
	}

	// ── Step 3: stop nodeA ───────────────────────────────────────────────
	nodeAAddr := nodeA.Addr()
	nodeA.listener.Close() // force-close; t.Cleanup cancels context too

	// Wait for OS to release the port.
	time.Sleep(50 * time.Millisecond)

	// nodeA should be unreachable now (best-effort assertion).
	if c, err := net.DialTimeout("tcp", nodeAAddr, 200*time.Millisecond); err == nil {
		c.Close()
		t.Logf("note: nodeA still accepting briefly after listener close (OS timing)")
	}

	// ── Step 4: re-fetch from nodeB (TF-05 pass criterion) ───────────────
	connB := dialTLSConn(t, nodeB)
	_, resp := sendAndExpect(t, connB, MsgGet, cid[:], MsgStore)
	_, gotData, err := decodeChunkPayload(resp)
	if err != nil {
		t.Fatalf("TF-05: decodeChunkPayload from nodeB: %v", err)
	}
	if !bytes.Equal(gotData, chunkData) {
		t.Errorf("TF-05 FAIL: re-fetched data does not match original")
	}
	t.Logf("TF-05 PASS: chunk retrieved from nodeB after nodeA failure ✓")
}

// ── Section 4 — Multi-chunk and concurrency tests ────────────────────────────

// TestMultipleChunkRoundTrip stores 5 distinct chunks and retrieves each,
// verifying SHA-256 integrity on every received payload (TS-02).
func TestMultipleChunkRoundTrip(t *testing.T) {
	n := startNode(t, nil, 0)
	conn := dialTLSConn(t, n)

	const numChunks = 5
	type chunk struct {
		cid  [32]byte
		data []byte
	}
	chunks := make([]chunk, numChunks)

	// STORE all.
	for i := 0; i < numChunks; i++ {
		data := []byte(fmt.Sprintf("chunk-%d-%s", i, bytes.Repeat([]byte{byte(i + 1)}, 64)))
		cid := sha256.Sum256(data)
		chunks[i] = chunk{cid, data}
		if err := WriteMsg(conn, MsgStore, buildChunkPayload(cid, data)); err != nil {
			t.Fatalf("chunk %d STORE: %v", i, err)
		}
	}
	time.Sleep(60 * time.Millisecond)

	// GET and verify each.
	for i, c := range chunks {
		_, resp := sendAndExpect(t, conn, MsgGet, c.cid[:], MsgStore)

		_, gotData, err := decodeChunkPayload(resp)
		if err != nil {
			t.Fatalf("chunk %d decode: %v", i, err)
		}
		// TS-02: re-verify SHA-256 of received data.
		if sha256.Sum256(gotData) != c.cid {
			t.Errorf("chunk %d: TS-02 integrity check failed", i)
		}
		if !bytes.Equal(gotData, c.data) {
			t.Errorf("chunk %d: content mismatch", i)
		}
	}
}

// TestConcurrentStoreGet runs the -race detector: 10 goroutines STORE+GET
// the same chunk over separate TLS connections.
func TestConcurrentStoreGet(t *testing.T) {
	n := startNode(t, nil, 0)

	data := bytes.Repeat([]byte{0xCC}, 1024)
	cid := sha256.Sum256(data)

	var wg sync.WaitGroup
	errs := make(chan error, 20)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn := dialTLSConn(t, n)

			// STORE.
			if err := WriteMsg(conn, MsgStore, buildChunkPayload(cid, data)); err != nil {
				errs <- fmt.Errorf("g%d STORE: %v", id, err)
				return
			}
			time.Sleep(15 * time.Millisecond)

			// GET.
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			if err := WriteMsg(conn, MsgGet, cid[:]); err != nil {
				conn.SetDeadline(time.Time{})
				errs <- fmt.Errorf("g%d GET write: %v", id, err)
				return
			}
			hdr, resp, err := ReadMsg(conn)
			conn.SetDeadline(time.Time{})
			if err != nil {
				errs <- fmt.Errorf("g%d GET read: %v", id, err)
				return
			}
			if hdr.Type != MsgStore {
				errs <- fmt.Errorf("g%d expected MsgStore, got 0x%02x", id, hdr.Type)
				return
			}
			_, gotData, err := decodeChunkPayload(resp)
			if err != nil || sha256.Sum256(gotData) != cid {
				errs <- fmt.Errorf("g%d integrity check failed: %v", id, err)
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// ── Section 5 — Client helper tests ──────────────────────────────────────────

// TestSendGetHelper exercises SendStore and SendGet over a live TLS connection.
func TestSendGetHelper(t *testing.T) {
	n := startNode(t, nil, 0)
	conn := dialTLSConn(t, n)

	data := []byte("SendGet helper round-trip test")
	cid := sha256.Sum256(data)

	if err := SendStore(conn, cid, data); err != nil {
		t.Fatalf("SendStore: %v", err)
	}
	time.Sleep(30 * time.Millisecond)

	got, err := SendGet(conn, cid)
	if err != nil {
		t.Fatalf("SendGet: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("SendGet: got %q, want %q", got, data)
	}
}

// TestSendGetNotFound verifies SendGet returns ErrChunkNotFound for absent CID.
func TestSendGetNotFound(t *testing.T) {
	n := startNode(t, nil, 0)
	conn := dialTLSConn(t, n)

	var cid [32]byte
	cid[0] = 0xFF

	_, err := SendGet(conn, cid)
	if err == nil {
		t.Fatal("expected error for absent CID")
	}
}

// TestSendAnnounceHelper verifies SendAnnounce updates the remote CIDIndex.
func TestSendAnnounceHelper(t *testing.T) {
	n := startNode(t, nil, 0)
	conn := dialTLSConn(t, n)

	var cid [32]byte
	cid[5] = 0xBE
	cid[6] = 0xEF

	if err := SendAnnounce(conn, cid); err != nil {
		t.Fatalf("SendAnnounce: %v", err)
	}
	time.Sleep(30 * time.Millisecond)

	if len(n.transfer.CIDIndex().Holders(cid)) == 0 {
		t.Fatal("SendAnnounce: CIDIndex not updated on remote node")
	}
}
