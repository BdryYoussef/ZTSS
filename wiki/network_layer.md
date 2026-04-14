# Network Layer

**Module:** `ztss-node/`  
**Owner:** Ziad Ghalban

## Node Architecture

- Language: **Go 1.22+**
- Server: **TCP multi-connection** with goroutines (one goroutine per connection)
- Deployment: **4 nodes** via `docker-compose.yml`

## Discovery Protocol

- Bootstrap: connect to **seed node** at startup
- Heartbeat: **ping/pong** messages
- Routing table maintained per node

## Binary Wire Protocol

```
[ Type:1B ][ Version:1B ][ Length:4B ][ CID:32B ][ Payload:NB ]
```

Message types:

| Hex | Name |
|-----|------|
| `0x01` | STORE |
| `0x02` | GET |
| `0x03` | ANNOUNCE |
| `0x04` | PING |
| `0x05` | PONG |

Header total: **16 bytes** (Type + Version + Length + CID + 2 bytes padding/reserved)

## Transport Security

- All inter-node channels: **TLS 1.3** OR **NOISE Protocol** (mandatory, no plaintext)
- `TS-01`: Wireshark capture must show no plaintext on inter-node traffic

## Node Configuration (YAML)

Required fields:
```yaml
port: <int>
storage_capacity: <bytes>
seeds:
  - <host>:<port>
```

## Required Files

```
ztss-node/
  node.go        # main server, goroutines
  discovery.go   # bootstrap, ping/pong, routing table
  transfer.go    # chunk upload/download inter-node
  node_test.go   # integration: node failure + re-routing
```

## Test Scenarios

- `TF-05`: 1 node cut → chunk re-fetched via alternate node
- Integration: node failure and re-routing
